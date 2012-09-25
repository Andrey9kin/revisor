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

#ifndef PATH_MAX
#define PATH_MAX 2000
#endif

#define FILES_MAX 20000

/* I'm too lazy to write nice dynamic array and then pass it to all functions
 * thats why we will use global static array of static length strings
 */
char opened_files_g[FILES_MAX][PATH_MAX];
char temp_files_g[FILES_MAX][PATH_MAX];
char exclude_patterns_g[FILES_MAX][PATH_MAX];

/* compare function used by qsort
*/
static int
str_sort_compare (const void * a, const void * b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

/* Handle opened file
 */
int
handle_opened_file(char* path_ptr)
{
  int i = 0;
  int empty = -1;
  char absp[PATH_MAX];
  struct stat file_stat;

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

    /* apply exclude pattern */
    if (strstr(absp,exclude_patterns_g[i]) != NULL)
      return EXIT_SUCCESS;
  }

  /* Check for dublicates */
  for (i=0;i<FILES_MAX;i++) {
    /* Exit function if path already in the list  */
    if (strcmp(opened_files_g[i],absp) == 0)
      return EXIT_SUCCESS;
  }

  /* Find next empty place in global files list
   * and check that opened file is not a temp file
   */
  for (i=0;i<FILES_MAX;i++) {
    /* i element is empty and it is first empty slot */
    if ((strcmp(opened_files_g[i],"") == 0) && (empty == -1))
      empty = i;
    if ((strcmp(absp,temp_files_g[i]) == 0)) /*path is temp file*/
      return EXIT_SUCCESS;
  }

  /* List is full */
  if (empty == -1) {
    fprintf(stderr, "To many opened files to handle\n");
    return EXIT_FAILURE;
  }

  /* copy path to files list */
  strcpy(opened_files_g[empty],absp);

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
  /* Terminate str */
  to[mhash_get_block_size(MHASH_MD5)] = '\0';

  return EXIT_SUCCESS;
}

/* Agregate results and put them to report file
 */
int
dump_result_to_file(char* reportfname)
{
  int i, j = 0;
  FILE *fp = NULL;
  unsigned char hash[100];
  int number_of_files = 0;
  char *sorted_files[FILES_MAX];

  /* Create file to record results */
  fp=fopen(reportfname, "w");

  /* Open file failed */
  if (fp == NULL) {
    fprintf(stderr, "Failed to create %s\n", reportfname);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  /* Copy to array of char-pointers, qsort need an array of pointers */
  for (i = 0; i < FILES_MAX; i++) {
    /* Stop if we have nothing to copy */
    if (strcmp(opened_files_g[i],"") == 0)
      break;

    /* Number of files in opened_files_g */
    number_of_files++;

    int str_length = strlen(opened_files_g[i]) + 1;
    char *path = (char*)malloc(str_length);
    strncpy(path, opened_files_g[i], str_length);
    sorted_files[i] = path;
  }

  /* sort by file path */
  qsort(sorted_files, number_of_files, sizeof (const char *), str_sort_compare);

  /* Print files and checksum to report file */
  for (i=0;i<number_of_files;i++) {

    /* Calculate md5 */
    if(calculate_md5((unsigned char*)&hash, sorted_files[i]) != 0) {
      fprintf(stderr, "Failed to calculate md5 for '%s'\n", sorted_files[i]);
      return EXIT_FAILURE;
    }


    for (j = 0; j < strlen((char *)hash); j++) {
      fprintf(fp,"%.2x",hash[j]);
    }
    fprintf(fp,"\t%s\n", sorted_files[i]);
  }

  /* free memory used by sorted file array */
  for (i=0;i<number_of_files;i++) {
    free(sorted_files[i]);
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



/* Read and save exclude rules
 */
int
load_exclude_rules(char* ignorefname)
{
  char temp_buffer[PATH_MAX];
  FILE *fp = NULL;
  int j = 0;
  int len = 0;
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
      /* Save rule in exclude list */
      strcpy(exclude_patterns_g[j],temp_buffer);
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
