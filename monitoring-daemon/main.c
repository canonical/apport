#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/select.h>
#include <time.h>
#include <sys/inotify.h>
#include <unistd.h>

void apport_get_event(int fd, char * target);
int main()
{
    int fd;
    fd = inotify_init ();
    if (fd < 0)
        perror ("inotify_init");
        
    int wd;
    wd = inotify_add_watch (fd,
                "/var/crash",
                IN_OPEN | IN_CLOSE_WRITE | IN_CREATE | IN_MODIFY);
    if (wd < 0)
        perror ("inotify_add_watch");    
    
    for (;;)
    {    
        apport_get_event(fd, "/var/crash");
    }    
    
    int ret1;
    ret1 = close (fd);
    if (ret1)
        perror ("close");    
        
    return 0;    
}

/* ----------------------------------------------------------------- */
/* Allow for 1024 simultanious events */
#define BUFF_SIZE ((sizeof(struct inotify_event)+FILENAME_MAX)*1024)

void apport_get_event (int fd, char * target)
{
    struct timeval time;
	fd_set rfds;
	int ret;

    ssize_t len, i = 0;
    char buff[BUFF_SIZE] = {0};
    pid_t pid;

    /* timeout after five seconds */
    time.tv_sec = 5;
    time.tv_usec = 0;

    /* zero-out the fd_set */
    FD_ZERO (&rfds);

    /*
     * add the inotify fd to the fd_set -- of course,
     * your application will probably want to add
     * other file descriptors here, too
     */
    FD_SET (fd, &rfds);

    ret = select (fd + 1, &rfds, NULL, NULL, &time);
    if (ret < 0)
            perror ("select");
    else if (FD_ISSET (fd, &rfds))
    {
        /* inotify events are available! */
        len = read (fd, buff, BUFF_SIZE);
        
        while (i < len) {
            struct inotify_event *pevent = (struct inotify_event *)&buff[i];

            if (pevent->mask & IN_CLOSE_WRITE) 
            {
                /* start apport report handler */

                pid = fork();
        
                if (pid == 0)
                {
                    (void)setenv("DISPLAY", ":0", 1);
                    /* Create a new SID for the child process */
                    (void)setsid();
                    /* Close out a standard file descriptor */
                    close(STDIN_FILENO);
                    /* FIXME add desktop recognition */
                    if (execl("/usr/share/apport/apport-gtk", "apport-gtk", NULL) != 0)
                        return;         
                }
            }            
      
            i += sizeof(struct inotify_event) + pevent->len;
        } /* while */
        
    } /* else if */
        

}  /* apport_get_event */

/* -- end of apport */
