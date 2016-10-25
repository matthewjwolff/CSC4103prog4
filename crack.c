#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include <crypt.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>

#define NUM_THREADS 4

/**
 * Original author: github.com/dcastl2
 */

void ith(char *password, int index, int n) {
  int i=1;
  for (i; i<=n; i++) {
    password[i-1] = (index % 26) + 'a';
    index /= 26;
  }
  password[n] = '\0';
}

// global pthread_mutex_t
pthread_mutex_t mutex;

// target hash in global memory (so all threads can access)
char target[16];

// The argument for the multithreaded routine
struct thread_func_arg {
  int start;
  int end;
};

/**
 * Runs dcastl2's decryption algorithm
 * Takes as argument the range of values this method should use
 * This implementation is thread-safe by use of pthread_mutex_lock
 */
void *thread_func(void *arg) {
  char *hash;
  char password[5];
  char salt[3];
  int M=pow(26,2);
  struct thread_func_arg *bounds = (struct thread_func_arg *) arg;
  int i=bounds->start;
  for(i; i<bounds->end; i++) {
    int j=0;
    for (j; j<M; j++) {
      ith(password, i, 4);
      ith(salt,     j, 2);
      // Lock mutex to examine crypt's static memory
      if(pthread_mutex_lock(&mutex)) {
        printf("Error locking mutex\n");
        exit(1);
      }
      hash = crypt(password, salt);
      if (0==strcmp(hash, target)) {
        printf("Password: %s\t\tSalt: %s\t\tHash: %s\t\tTarget: %s\n", password, salt, hash, target);
        exit(0);
      } else pthread_mutex_unlock(&mutex);
    }
  }
}

int main() {
  if(pthread_mutex_init(&mutex, NULL)) {
    printf("Error initializing mutex\n");
    exit(-1);
  }

  int N=pow(26, 4);

  int fd  = open("hash.txt", 'r');
  int num = read(fd, target, 16);
  if (num) target[num-1] = 0;
  else     exit(-1);
  close(fd);

  int size = N/NUM_THREADS;
  int i=0;
  struct thread_func_arg args[NUM_THREADS];
  pthread_t threads[NUM_THREADS];
  for(i; i<NUM_THREADS; i++) {
    int start = (N/NUM_THREADS)*i;
    // in case of integer division, make the last thread take anything left
    int end = i==(NUM_THREADS-1) ? N : (N/NUM_THREADS)*(i+1) - 1;
    args[i].start = start;
    args[i].end = end;
    if(pthread_create(threads+i, NULL, thread_func, args + i)) {
      printf("Couldn't spin up thread\n");
      exit(-1);
    }
  }
  i=0;
  for(i; i<NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
    printf("Thread %ld terminated with no hits...\n", threads[i]);
  }
}
