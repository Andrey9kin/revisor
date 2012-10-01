#include "defs.h"
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <mhash.h>
#include <regex.h>
#include <glib.h>

#ifndef PATH_MAX
#define PATH_MAX 2000
#endif

#define FILES_MAX 120000

/* I'm too lazy to write nice dynamic array and then pass it to all functions
 * thats why we will use global static array of static length strings
 */
char opened_files_g[FILES_MAX][PATH_MAX];
char exclude_patterns_g[FILES_MAX][PATH_MAX];

int index_g;
char *sorted_files_g[FILES_MAX];
GTree* tracked_files_tree_g;
regex_t *exclude_patterns_compiled_regex_g[FILES_MAX];



/* Handle opened file
 */
int
handle_opened_file(char* path_ptr)
{
  int i = 0;
  int reti;
  char absp[PATH_MAX];
  char msgbuf[100];
  struct stat file_stat;
  regex_t regex;
  /* Skip files that doesn't exist */
  if (stat(path_ptr, &file_stat) < 0)
    return EXIT_SUCCESS;

  /* Not intrested in directories */
  if (S_ISDIR(file_stat.st_mode))
    return EXIT_SUCCESS;

  /* TODO: get actual file and check */
  if (S_ISLNK(file_stat.st_mode))
    return EXIT_SUCCESS;

  if (realpath(path_ptr, absp) == NULL) {
    fprintf(stderr, "realpath failed for %s\n",path_ptr);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  /* Try to apply exclude rules */
  for (i=0;i<FILES_MAX;i++) {
    /* skip whole list check, exit loop if first empty slot met */
    if (strcmp(exclude_patterns_g[i],"") == 0) break;

  }

  /* Try to apply exclude regexp */
  for (i=0;i<FILES_MAX;i++) {
    /* skip whole list check, exit loop if first empty slot met */
    if (exclude_patterns_compiled_regex_g[i] == NULL) break;

    /* apply exclude pattern */
    reti = regexec(exclude_patterns_compiled_regex_g[i], absp, 0, NULL, 0);
    if (!reti) {
      /* Match to exclude pattern, skip */
      return EXIT_SUCCESS;
    } else if (reti != REG_NOMATCH) {
      /* Got a error */
      regerror(reti, &regex, msgbuf, sizeof(msgbuf));
      fprintf(stderr, "Regex match failed: %s\n", msgbuf);
      return EXIT_FAILURE;
    }
  }


  /* Exit function if path already in the tree  */
  if(g_tree_lookup(tracked_files_tree_g, absp) != NULL) {
    return EXIT_SUCCESS;
  }

  /* Copy string */
  int str_length = strlen(absp) + 1;
  char *path = (char*)malloc(str_length);
  strncpy(path, absp, str_length);

  /* Store string */
  g_tree_insert(tracked_files_tree_g, path, NULL);

  return EXIT_SUCCESS;
}

/* Handle opened file
 */
int
update_ignore_list(char* path_ptr)
{
  int i = 0;
  int empty = -1;

  /* Try to apply exclude rules */
  for (i=0;i<FILES_MAX;i++) {
    /* skip whole list check, exit loop if first empty slot met */
    if (strcmp(exclude_patterns_g[i],"") == 0) {
      empty = i;
      break;
    }

    /* Exit if file already it the list */
    if (strcmp(exclude_patterns_g[i],path_ptr) == 0)
      return EXIT_SUCCESS;
  }

  if (empty == -1) {
    fprintf(stderr, "To many ignore files to handle\n");
    return EXIT_FAILURE;
  }

  /* copy path to files list */
  strcpy(exclude_patterns_g[empty],path_ptr);

  return EXIT_SUCCESS;
}


int 
compile_and_store_regex(const char *pattern_ptr, regex_t *regex_ptr) {
  int reti = 0;
  /* Compile regular expression */
  reti = regcomp(regex_ptr, pattern_ptr, 0);
  if( reti ) {
    fprintf(stderr, "Could not compile regex\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

/* Calculate md5
*/
int
calculate_md5(unsigned char *to, const char *file_path)
{
  int i;
  MHASH td;
  FILE *fp;
  struct stat sb;
  size_t bytes_read;
  unsigned char *hash;
  unsigned char *data;

  /* Initiate algorithm type context descriptor */
  td = mhash_init(MHASH_MD5);

  /* Initiation failed */
  if (td == MHASH_FAILED) {
    fprintf(stderr, "md5 algorithm descriptor initiation failed\n");
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  /* Get file size */
  if (stat(file_path, &sb) != 0) {
    fprintf (stderr, "stat failed for '%s'\n",file_path);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return (EXIT_FAILURE);
  }

  /* Allocate memory for entire file */
  data = malloc (sb.st_size + 1);
  if (!data) {
      fprintf (stderr, "Out of memory error.\n");
      return EXIT_FAILURE;
  }

  /* open file */
  fp = fopen(file_path, "r");

  /* Open file failed */
  if (fp == NULL) {
    fprintf(stderr, "Failed to open %s\n", file_path);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  /* Read all data into memory */
  bytes_read = fread(data, sizeof (unsigned char), sb.st_size, fp);
  if(bytes_read != sb.st_size) {
    fprintf(stderr, "Error: bytes read '%Zd', expected '%Zd'\n", bytes_read, sb.st_size);
    return EXIT_FAILURE;
  }

  /* Close file to save results */
  /* Close file failed */
  if (fclose(fp) != 0) {
    fprintf(stderr, "Failed to close %s\n", file_path);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  /* Calculate md5 */
  mhash(td, data, sb.st_size);
  hash = mhash_end(td);

  /* release memory used to store file data */
  free(data);

  /* Copy md5 into supplied 'char *' */
  for (i = 0; i < mhash_get_block_size(MHASH_MD5); i++) {
    to[i] = hash[i];
  }
  
  /* Free memory allocated by MD5 checksum calculation */
  free(hash);
  
  return EXIT_SUCCESS;
}

/* Move files from tree to sorted array
*/
gboolean
iter_all(gpointer key, gpointer value, gpointer data) {
  sorted_files_g[index_g] = (char *)key;
  index_g++;
  return FALSE;
}


/* Agregate results and put them to report file
 */
int
dump_result_to_file(char* reportfname)
{
  int i = 0;
  int j = 0;
  FILE *fp = NULL;
  unsigned char hash[mhash_get_block_size(MHASH_MD5)];

  /* Create file to record results */
  fp=fopen(reportfname, "w");

  /* Open file failed */
  if (fp == NULL) {
    fprintf(stderr, "Failed to create %s\n", reportfname);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }


  /* Copy char pointers from 'tracked_files_tree_g' to 'sorted_files_g' */
  index_g = 0;
  g_tree_foreach(tracked_files_tree_g, (GTraverseFunc)iter_all, NULL);

  /* Print to file */
  for (i = 0; i < FILES_MAX; i++) {
    if(sorted_files_g[i] == NULL)
      break;

    /* Calculate md5 */
    if(calculate_md5((unsigned char*)&hash, sorted_files_g[i]) != 0) {
      fprintf(stderr, "Failed to calculate md5 for '%s'\n", sorted_files_g[i]);
      return TRUE;
    }

    for (j = 0; j < mhash_get_block_size(MHASH_MD5); j++) {
      fprintf(fp,"%.2x",hash[j]);
    }
    fprintf(fp,"\t%s\n", sorted_files_g[i]);
  }

  /* free memory used by tree */
  for (i = 0; i < FILES_MAX; i++) {
    if(sorted_files_g[i] == NULL)
      break;
    free(sorted_files_g[i]);
  }

  for (i=0;i<FILES_MAX;i++) {
    if(exclude_patterns_compiled_regex_g[i] == NULL)
      break;

    /* Free compiled regular expression */
    regfree(exclude_patterns_compiled_regex_g[i]);
  }

  /* Close file to save results */
  /* Close file failed */
  if (fclose(fp) != 0) {
    fprintf(stderr, "Failed to close %s\n", reportfname);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/* Create the binary tree-structure
*/
int
init_tree_structures() {
  tracked_files_tree_g = g_tree_new((GCompareFunc)g_ascii_strcasecmp);
  if(tracked_files_tree_g == NULL) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}


/* Read and save exclude rules
 */
int
load_exclude_rules(char* ignorefname)
{
  char temp_buffer[PATH_MAX];
  FILE *fp = NULL;
  int j = 0;
  int len = 0;
  int reti;
  regex_t *regex;
  struct stat file_stat;

  /* No file no rules */
  if (ignorefname == NULL)
    return EXIT_SUCCESS;

  /* Skip files that doesn't exist */
  if (stat(ignorefname, &file_stat) < 0) {
    fprintf(stderr,"%s no such file\n",ignorefname);
    return EXIT_FAILURE;
  }

  /* Read ignore rules */
  fp=fopen(ignorefname, "r");

  /* Open file failed */
  if (fp == NULL) {
    fprintf(stderr,"Failed to open %s\n",ignorefname);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  /* Read file till the end */
  while(fgets(temp_buffer,PATH_MAX,fp) != NULL)
    {
      /* Remove newline character added by fgets */
      len = strlen(temp_buffer);
      if( temp_buffer[len-1] == '\n' )
	temp_buffer[len-1] = 0;

      
      /* allocate memory */
      regex = malloc(sizeof(regex_t));
      if (!regex) {
        fprintf (stderr, "Out of memory error.\n");
        return EXIT_FAILURE;
      }

      /* Compile regex */
      reti = compile_and_store_regex(temp_buffer, regex);
      if(reti != EXIT_SUCCESS) {
        return reti;
      }

      /* Save rule in exclude list */
      exclude_patterns_compiled_regex_g[j] = regex;
      j++;
    }

  /* Close file failed */
  if (fclose(fp) != 0) {
      fprintf(stderr,"Failed to close %s\n",ignorefname);
      fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
      return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
