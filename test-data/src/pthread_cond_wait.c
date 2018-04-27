#include <pthread.h>
#include <sys/prctl.h>

pthread_cond_t cond;
pthread_mutex_t mutex;

void * thread_main(void * arg) {
    prctl(PR_SET_NAME, (unsigned long)"another thread", 0, 0, 0);
    for (;;) {
        pthread_mutex_lock(&mutex);
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);
    }
    return 0;
}

int main() {
    pthread_cond_init(&cond, 0);
    pthread_mutex_init(&mutex, 0);

    pthread_mutex_lock(&mutex);

    pthread_t thread;
    pthread_create(&thread, 0, thread_main, 0);
    for (;;) {
        pthread_cond_wait(&cond, &mutex);
    }

    return 0;
}
