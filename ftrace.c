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

/* Agregate results and put them to report file
 */
int
dump_result_to_file(char* reportfname)
{
  int i = 0;
  unsigned int hash = 0;
  MHASH td;
  FILE *fp = NULL;

  /* Create file to record results */
  fp=fopen(reportfname, "w");

  /* Open file failed */
  if (fp == NULL) {
    fprintf(stderr, "Failed to create %s\n", reportfname);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  /* Print files and checksum to report file */
  for (i=0;i<FILES_MAX;i++) {
    /* Stop if we have nothing to print */
    if (strcmp(opened_files_g[i],"") == 0)
      break;

    /* Initiate algorithm type context descriptor */
    td = mhash_init(MHASH_MD5);

    /* Initiation failed */
    if (td == MHASH_FAILED) {
      fprintf(stderr, "md5 algorithm descriptor initiation failed\n");
      fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
      return EXIT_FAILURE;
    }

    mhash(td, opened_files_g[i], strlen(opened_files_g[i]));

    mhash_deinit(td, &hash);

    fprintf(fp,"%-10x\t%s\n",hash,opened_files_g[i]);
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
