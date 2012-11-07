#include "defs.h"
#include <dirent.h>
#include <errno.h>
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

#define REGEX_MAX 1000

/* This is the last created file (it probably didn't exist before the call to create) */
char *last_created_g;

/* used to keep track of */
int sorted_files_index_g;

/* The value stored in all tree-nodes so that the lookup function don't return NULL */
int tree_value_g;

/* This is allocated and filled by a callback function during tree traversal */
char **sorted_files_g;

/* The two trees (ignore tree is used because regexp is many times slower) */
GTree *tracked_files_tree_g;
GTree *ignore_files_tree_g;

/* Used for storing pre-compiled regex exclusion patterns */
regex_t *exclude_patterns_compiled_regex_g[REGEX_MAX];

/* Remove /bla/../bla and /bla/./bla/ patterns from the path */
int
normalize_path(char *output, char *input) {
  char result[PATH_MAX]="";
  size_t resultlen = 0;
  size_t currentlen = 0;

  char *current = input;
  char *end = &input[strlen(input)];
  char *next = NULL;
  char *slash = NULL;

  /* Check input */
  if (input == NULL) {
    fprintf(stderr,"Internal error! Empty input for %s\n",
	    __FUNCTION__);
    return EXIT_FAILURE;
  }

  /* Go slash by slash and fix stuff if we have sonething to fix */
  for (current = input; current < end; current=next+1) {
    /* Get pointer to next slash */
    next = memchr(current, '/', end-current);

    /* stop if not found */
    if (next == NULL) {
      next = end;
    }

    /* Calculate len of current segment */
    currentlen = next-current;

    /* if current segment len is one or two then we check them */
    switch(currentlen) {
    case 2:
      if (current[0] == '.' && current[1] == '.') {
	slash = memrchr(result, '/', resultlen);
	if (slash != NULL) {
	  resultlen = slash - result;
	}
	continue;
      }
      break;
    case 1:
      if (current[0] == '.') {
	continue;
      }
      break;
    case 0:
      continue;
    }
    result[resultlen++] = '/';
    memcpy(&result[resultlen], current, currentlen);
    resultlen += currentlen;
  }

  if (resultlen == 0) {
    result[resultlen++] = '/';
  }

  result[resultlen] = '\0';
  strcpy(output,result);

  return EXIT_SUCCESS;
}

/* Move files from tree to sorted array
*/
gboolean
iter_all(gpointer key, gpointer value, gpointer data) {
  sorted_files_g[sorted_files_index_g] = (char *)key;
  sorted_files_index_g++;
  return FALSE;
}

/* free memory used by the string key
* This is a callback method called for each key by g_tree_destroy
*/
void
destroy_key(gpointer data) {
  free((char *)data);
}

/* This function should only be called on files that exist
*/
int
add_file_to_ignore_filter(char* path_ptr)
{
  char *path;
  char absp[PATH_MAX];

  if (path_ptr == NULL) {
    fprintf(stderr,"Internal error! Empty input for %s\n",
	    __FUNCTION__);
    return EXIT_FAILURE;
  }

  /* get absolute path */
  if (realpath(path_ptr, absp) == NULL) {
    fprintf(stderr, "realpath failed for %s\n",path_ptr);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return EXIT_FAILURE;
  }

  /* Exit function if path already is in the tree  */
  if(g_tree_lookup(ignore_files_tree_g, absp) != NULL) {
    return EXIT_SUCCESS;
  }

  /* Store string in ignore tree */
  path = strdup(absp);
  g_tree_insert(ignore_files_tree_g, path, &tree_value_g);

  return EXIT_SUCCESS;
}

/* Check if the file should be processed (added to tracking and/or ignore filter)
*/
int
should_file_be_processed(char* path_ptr)
{
  struct stat file_stat;

  /* Skip files that doesn't exist */
  if (stat(path_ptr, &file_stat) < 0)
    return 0;

  /* Not intrested in directories */
  if (S_ISDIR(file_stat.st_mode))
    return 0;

  /* TODO: get actual file and check */
  if (S_ISLNK(file_stat.st_mode))
    return 0;

  return 1;
}

/* Handle opened file
 */
int
handle_opened_file(char* path_ptr)
{
  int i = 0;
  int reti;
  char *path;
  char absp[PATH_MAX];
  char msgbuf[100];
  regex_t regex;

  /* Check file from last ignore call */
  if(last_created_g != NULL) {
    if(should_file_be_processed(last_created_g)) {
      add_file_to_ignore_filter(last_created_g);
      free((char *)last_created_g);
      last_created_g = NULL;
    }
  }

  /* Check if file should be processed */
  if(!should_file_be_processed(path_ptr)) {
    return EXIT_SUCCESS;
  }

  /* Fix up path */
  if (normalize_path(absp, path_ptr) == EXIT_FAILURE) {
    fprintf(stderr, "Path normalization failed for %s\n",path_ptr);
    return EXIT_FAILURE;
  }

  /* Exit function if path already is in the ignore tree  */
  if(g_tree_lookup(ignore_files_tree_g, absp) != NULL) {
    return EXIT_SUCCESS;
  }

  /* Exit function if path already is in the tree  */
  if(g_tree_lookup(tracked_files_tree_g, absp) != NULL) {
    return EXIT_SUCCESS;
  }

  /* Try to apply exclude regexp */
  for (i=0;i<REGEX_MAX;i++) {
    /* skip whole list check, exit loop if first empty slot met */
    if (exclude_patterns_compiled_regex_g[i] == NULL) break;

    /* apply exclude pattern */
    reti = regexec(exclude_patterns_compiled_regex_g[i], absp, 0, NULL, 0);

    if (!reti) {
      /* Match to exclude pattern,
       * add to ignore tree and skip
       */
      path = strdup(absp);
      g_tree_insert(ignore_files_tree_g, path, &tree_value_g);

      return EXIT_SUCCESS;
    } else if (reti != REG_NOMATCH) {
      /* Got a error */
      regerror(reti, &regex, msgbuf, sizeof(msgbuf));
      fprintf(stderr, "Regex match failed: %s\n", msgbuf);
      return EXIT_FAILURE;
    }
  }

  /* Store string in tracked files */
  path = strdup(absp);
  g_tree_insert(tracked_files_tree_g, path, &tree_value_g);

  return EXIT_SUCCESS;
}


/* Handle file that should be ignored
 */
int
update_ignore_list(char* path_ptr)
{
  /* Check file from last ignore call */
  if(last_created_g != NULL)
  {
    if(should_file_be_processed(last_created_g)) {
      add_file_to_ignore_filter(last_created_g);
      free((char *)last_created_g);
      last_created_g = NULL;
    }
  }

  /* Check file for this ignore */
  if(should_file_be_processed(path_ptr)) {
    add_file_to_ignore_filter(path_ptr);
  } else {
    /* Change so that 'path_ptr'-path is stored in 'last_created_g' */
    if(last_created_g != NULL) {
      free((char *)last_created_g);
    }
    last_created_g = strdup(path_ptr);
  }
  return EXIT_SUCCESS;
}

/* Precompile regex
*/
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
    /* Permission denied, lets skip those files. */
    if (errno == EACCES) {
      return EXIT_SUCCESS;
    }
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

/* Check path for environment variables and replace them
 * with environment variables value
*/
int
replace_env_variables(char *result_ptr, char *input_path_ptr)
{
  int i = 0;
  int j = 0;
  int last = 0;
  char path[PATH_MAX] = "";
  char name[PATH_MAX] = "";
  char *value_ptr = NULL;

  /* Check input */
  if (input_path_ptr == NULL) {
    fprintf(stderr,"Empty string provided as input to %s function\n",__func__);
    return EXIT_FAILURE;
  }

  for (i=0;i<strlen(input_path_ptr);i++) {
    /* If $ found */
    if ('$' == input_path_ptr[i]) {
      /* Look for environment variable name end */
      for (j=i;j<strlen(input_path_ptr);j++) {
	if ('/' == input_path_ptr[j]) {
	  break;
	}
      }
      /* Extract env variable name */
      strncpy(name,input_path_ptr+i+1,j-i-1);
      /* Get variable value */
      value_ptr = getenv(name);
      /* Error if not found */
      if (value_ptr == NULL) {
	fprintf(stderr,"Env variable %s used in the report is not set in the current env\n",name);
	return EXIT_FAILURE;
      }

      if (last == 0) { /* First env variable found */
	/* first env variable in the midle of the line (we don't check
	 * env variable in the beginning becasuse there is nothing to do with it
	 */
	if (i > 0) {
	  /* take first i-1 bytes in the path */
	  strncpy(path,input_path_ptr,i-1);
	}
      } else if (last > 0) { /* Not the first env variable */
	/* Add to the end path variable path from the end of last env variable
	 * till current env variable name start
	 */
	strncpy(path+strlen(path),input_path_ptr+last,i-last);
      } else if (last < 0) { /* Something is completly wrong */
	fprintf(stderr,"Something is really broken here...\n");
	return EXIT_FAILURE;
      }

      /* Add value of env variable */
      strcat(path,value_ptr);
      /* Remember position for env variable name end */
      last = j;
      /* Seek index to the current env variable end */
      i=j;
      /* Clean name */
      memset(name, 0, sizeof(name));;
    }
  }

  /* Add remaining part of the string */
  strcat(path,input_path_ptr+last);

  /* Return result */
  strcpy(result_ptr,path);

  return EXIT_SUCCESS;
}

/* Agregate results and put them to report file
 */
int
dump_result_to_file(char* reportfname, char** substitute_environment_variables)
{
  int i = 0;
  int j = 0;
  int k = 0;
  int nnodes = 0;;
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

  /* Setup before copy */
  sorted_files_index_g = 0;
  nnodes = g_tree_nnodes(tracked_files_tree_g);

  sorted_files_g = malloc(sizeof(char *) * nnodes);
  if (!sorted_files_g) {
    fprintf (stderr, "Out of memory error.\n");
    return EXIT_FAILURE;
  }

  /* Copy char pointers from 'tracked_files_tree_g' to 'sorted_files_g' */
  g_tree_foreach(tracked_files_tree_g, (GTraverseFunc)iter_all, NULL);

  /* Print to file */
  for (i = 0; i < nnodes; i++) {
    if(sorted_files_g[i] == NULL)
      break;

    /* Additional check in case of race conditionds  */
    if(g_tree_lookup(ignore_files_tree_g, sorted_files_g[i]) != NULL)
      continue;

    /* Calculate md5 */
    if(calculate_md5((unsigned char*)&hash, sorted_files_g[i]) != 0) {
      fprintf(stderr, "Failed to calculate md5 for '%s'\n", sorted_files_g[i]);
    }

    for (j = 0; j < mhash_get_block_size(MHASH_MD5); j++) {
      fprintf(fp,"%.2x",hash[j]);
    }


    for(k = 0;k < MAX_S_ENV;k++) {
      if (substitute_environment_variables[k] == NULL) {
        /* No match */
        fprintf(fp,"\t%s\n", sorted_files_g[i]);
        break;
      }
      char* env_str = getenv(substitute_environment_variables[k]);
      if(strstr(sorted_files_g[i], env_str)) {
        /* Match */
        fprintf(fp,"\t$%s%s\n", substitute_environment_variables[k], sorted_files_g[i] + strlen(env_str));
        break;
      }
    }
  }

  /* free memory used by tree (this will also free 'sorted_files_g' since it point to the same memory */
  g_tree_destroy(tracked_files_tree_g);
  g_tree_destroy(ignore_files_tree_g);

  /* Free compiled regular expression */
  for (i=0;i<REGEX_MAX;i++) {
    if(exclude_patterns_compiled_regex_g[i] == NULL)
      break;
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

/* Read report and check fiels for changes
 */
int
check_for_changes(char* inputfname)
{
  unsigned char ucurrent_hash[mhash_get_block_size(MHASH_MD5)];
  char temp_buffer[PATH_MAX + mhash_get_block_size(MHASH_MD5) +1];
  char input_hash[mhash_get_block_size(MHASH_MD5)];
  char current_hash[mhash_get_block_size(MHASH_MD5)*2 +1];
  char path[PATH_MAX];
  int i = 0;
  char *loc_ptr = NULL;
  FILE *fp_ptr = NULL;
  struct stat file_stat;

  /* No file no check */
  if (inputfname == NULL)
    return REVISOR_TRIGGER_CHANGES_FOUND;

  /* Still, no file no check */
  if (stat(inputfname, &file_stat) < 0) {
    return REVISOR_TRIGGER_CHANGES_FOUND;
  }

  /* Read input file */
  fp_ptr=fopen(inputfname, "r");

  /* Open file failed */
  if (fp_ptr == NULL) {
    fprintf(stderr,"Failed to open %s\n",inputfname);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return REVISOR_TRIGGER_ERROR;
  }

  /* Read file till the end */
  while(fgets(temp_buffer,PATH_MAX,fp_ptr) != NULL) {

    /* Remove newline character added by fgets */
    if( temp_buffer[strlen(temp_buffer)-1] == '\n' )
       temp_buffer[strlen(temp_buffer)-1] = 0;

    /* check line for delimeter and get pointer to the hash */
    loc_ptr = strtok(temp_buffer,"\t");

    /* Something wrong with input file structure */
    if (loc_ptr == NULL) {
      fprintf(stderr,"Could not find delimiter in the %s line\n",temp_buffer);
      return REVISOR_TRIGGER_ERROR;
    }

    /* Copy hash to separate variable */
    if (!strcpy(input_hash,loc_ptr)) {
	fprintf(stderr,"Failed to extract hash from %s\n",temp_buffer);
	fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
	return REVISOR_TRIGGER_ERROR;
    }

    /* Get pointer to path */
    loc_ptr = strtok(NULL, "\t");

    /* Something wrong with input file structure */
    if (loc_ptr == NULL) {
      fprintf(stderr,"Could not find path in the %s line\n",temp_buffer);
      return REVISOR_TRIGGER_ERROR;
    }

    /* Get real path without env variables in it */
    if (replace_env_variables((char*)&path,loc_ptr) == EXIT_FAILURE) {
      return REVISOR_TRIGGER_ERROR;
    }

    /* Can't find file from the report - consider rebuild */
    if (stat(path, &file_stat) < 0) {
      fprintf(stdout, "%s stated in %s was not found. Consider rebuild\n",
	      path,
	      inputfname);
      return REVISOR_TRIGGER_CHANGES_FOUND;
    }

    /* Calculate md5 for the file extracted from the input file */
    if (calculate_md5((unsigned char*)&ucurrent_hash, path) != 0) {
      fprintf(stderr, "Failed to calculate md5 for '%s'\n", path);
      return REVISOR_TRIGGER_ERROR;
    }

    /* We need to transform hash to string to be able to compare it
       with hash from the file */
    for(i=0;i<mhash_get_block_size(MHASH_MD5);i++) {
      sprintf(&current_hash[2*i], "%.2x", ucurrent_hash[i]);
    }

    /* Compare hash's */
    if (strcmp(current_hash,input_hash) != 0) {
      /* Changes found. Return success to continue with build */
      /* Close file failed */
      if (fclose(fp_ptr) != 0) {
	fprintf(stderr,"Failed to close %s\n",inputfname);
	fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
	return REVISOR_TRIGGER_ERROR;
      }
      return  REVISOR_TRIGGER_CHANGES_FOUND;
    }
  }

  /* Close file failed */
  if (fclose(fp_ptr) != 0) {
    fprintf(stderr,"Failed to close %s\n",inputfname);
    fprintf(stderr,"Error: %s, errno=%d\n",strerror(errno),errno);
    return REVISOR_TRIGGER_ERROR;
  }

  return REVISOR_TRIGGER_NO_CHANGES_FOUND;
}

/* Create the binary tree-structure
*/
int
init_tree_structures() {
  /* Set a value so that it isn't zero */
  tree_value_g = 42;

  /* Should always be null at execution start */
  last_created_g = NULL;

  tracked_files_tree_g = g_tree_new_full((GCompareDataFunc)g_ascii_strcasecmp, NULL, (GDestroyNotify)destroy_key, NULL);
  if(tracked_files_tree_g == NULL) {
    return EXIT_FAILURE;
  }

  ignore_files_tree_g = g_tree_new_full((GCompareDataFunc)g_ascii_strcasecmp, NULL, (GDestroyNotify)destroy_key, NULL);
  if(ignore_files_tree_g == NULL) {
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

