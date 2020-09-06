#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "inotify-nosys.h"

#define BLOCKING_TIMEOUT -1

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#endif
#define EXIT_TIMEOUT 2

#define MAX_STRLEN 4096
#define MAX_EVENTS 4096

static int error = 0;
static int inotify_fd = 0;
static int socket_fd = -1;
static int monitor = 1;

//
// We do POSIX. Write Once, Run Everywhere.
//
int asprintf(char **ret, const char *format, ...)
{
    va_list ap;

    *ret = NULL;  /* Ensure value can be passed to free() */

    va_start(ap, format);
    int count = vsnprintf(NULL, 0, format, ap);
    va_end(ap);

    if (count >= 0)
    {
        char* buffer = malloc(count + 1);
        if (buffer == NULL)
            return -1;

        va_start(ap, format);
        count = vsnprintf(buffer, count + 1, format, ap);
        va_end(ap);

        if (count < 0)
        {
            free(buffer);
            return count;
        }
        *ret = buffer;
    }

    return count;
}

int inotify_initialize()
{
	error = 0;
	
	inotify_fd = inotify_init();
	if (inotify_fd < 0)	{
		error = errno;
		return 1;
	}

	return 0;
}

int isdir(char const *path)
{
    static struct stat my_stat;

    if (-1 == lstat(path, &my_stat)) {
        if (errno == ENOENT)
            return 0;
        fprintf(stderr, "Stat failed on %s: %s\n", path, strerror(errno));
        return 0;
    }

    return S_ISDIR(my_stat.st_mode) && !S_ISLNK(my_stat.st_mode);
}

struct inotify_event * 
inotifytools_next_events( long int timeout ) 
{
	static struct inotify_event event[MAX_EVENTS];
	static struct inotify_event * ret;
	static int first_byte = 0;
	static ssize_t bytes;

	error = 0;

	//
	// First_byte is index into event buffer
	//
	if ( first_byte != 0
	  && first_byte <= (int)(bytes - sizeof(struct inotify_event)) ) {

		ret = (struct inotify_event *)((char *)&event[0] + first_byte);
		first_byte += sizeof(struct inotify_event) + ret->len;

		if ( first_byte == bytes ) {
			first_byte = 0;
		}
		return ret;
	}
	else if ( first_byte == 0 ) {
		bytes = 0;
	}

	static ssize_t this_bytes;
	static unsigned int bytes_to_read;
	static int rc;
	static fd_set read_fds;

	static struct timeval read_timeout;
	read_timeout.tv_sec = timeout;
	read_timeout.tv_usec = 0;
	static struct timeval * read_timeout_ptr;
	read_timeout_ptr = ( timeout < 0 ? NULL : &read_timeout );

	FD_ZERO(&read_fds);
	FD_SET(inotify_fd, &read_fds);
	rc = select(inotify_fd + 1, &read_fds, NULL, NULL, read_timeout_ptr);
	if ( rc < 0 ) {
		// error
		error = errno;
		return NULL;
	}
	else if ( rc == 0 ) {
		// timeout
		return NULL;
	}

	//
	// Wait until we have enough bytes to read
	//
	do {
		rc = ioctl( inotify_fd, FIONREAD, &bytes_to_read );
	} while ( !rc && bytes_to_read < sizeof(struct inotify_event) );

	if ( rc == -1 ) {
		error = errno;
		return NULL;
	}

	this_bytes = read(inotify_fd, &event[0] + bytes,
	                  sizeof(struct inotify_event)*MAX_EVENTS - bytes);
	if ( this_bytes < 0 ) {
		error = errno;
		return NULL;
	}
	if ( this_bytes == 0 ) {
		fprintf(stderr, "Inotify reported end-of-file.  Possibly too many "
		                "events occurred at once.\n");
		return NULL;
	}
	bytes += this_bytes;

	ret = &event[0];
	first_byte = sizeof(struct inotify_event) + ret->len;
	if (first_byte > bytes)
	    fprintf(stderr, "ridiculously long filename, things will "
	                                 "almost certainly screw up." );
	if ( first_byte == bytes ) {
		first_byte = 0;
	}

	return ret;
}

int remove_inotify_watch(int wd) 
{
	error = 0;
	int status = inotify_rm_watch( inotify_fd, wd );
	if ( status < 0 ) {
		error = status;
		return 1;
	}
	return 0;
}


int watch_inode(char const *inode, int events)
{
	error = 0;

	static int wd;
	
	wd = inotify_add_watch( inotify_fd, inode, events );
	
	if ( wd < 0 ) {
		if ( wd == -1 ) {
			error = errno;
			return 0;
		}
		else {
			fprintf( stderr, "Failed to watch %s: returned wd was %d "
			         "(expected -1 or >0 )", inode, wd );
			return 0;
		}
	}

	char *filename;

	// Always end filename with / if it is a directory
	if ( !isdir(inode)
	     || inode[strlen(inode)-1] == '/') {
		filename = strdup(inode);
	}
	else {
		asprintf( &filename, "%s/", inode );
	}
	free(filename);

	return 1;
}

int watch(const char *inode, int events)
{
    long int timeout = BLOCKING_TIMEOUT;

    if (!watch_inode(inode, events)) {
        if (error == ENOSPC) {
            fprintf(stdout,
                 "Failed to watch %s; upper limit on inotify "
                 "watches reached!\n",
                 inode
		 );
            fprintf(stdout,
                 "Please increase the amount of inotify watches "
                 "allowed per user via `/proc/sys/fs/inotify/"
                 "max_user_watches'.\n"
		 );
        } else {
            fprintf(stderr, "Couldn't watch %s: %s\n", inode, strerror(error));
        }
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Watches established.\n");

    //
    // Now wait till we get event
    //
    struct inotify_event *event;

    do {
	// wait and parse inotify event
        event = inotifytools_next_events(timeout);
        if (!event) {
            if (!error) {
		    fprintf(stderr, "EXIT_TIMEOUT\n");
                return EXIT_TIMEOUT;
            } else {
                fprintf(stderr, "%s\n", strerror(error));
		    fprintf(stderr, "EXIT_FAILURE\n");
                return EXIT_FAILURE;
            }
        }

        if (event->mask) {
	    fprintf(stdout, "%X\n", event->mask);

	    //
	    // Send datagram to GUI server if online
	    //
	    if (socket_fd != -1) {
                //if( send(socket_fd, event, sizeof(struct inotify_event), 0) < 0) // ###
		if (send(socket_fd, &event->mask, sizeof(int), 0) < 0)
	       	{
                    fprintf(stderr, "Send failed");
                }
	    }
        }

        fflush(NULL);

    } while (monitor);

    if ((events & event->mask) == 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void SigPoll(int signum)
{
	(void) signum;
        /* XXX Note:  Technically speaking, fprintf in a signal handler
         * is illegal and should be avoided.  In fact, most of libc is
         * not allowed in a signal handling function.  See W. Richard Steven's
         * book entitled "Advanced Programming in the UNIX Environment"
         * pp. 278-279 for further discussion.
         */
        /* fprintf(stdout, "caught SIGPOLL\n"); */
        write(1,"caught SIGPOLL\n",sizeof("caught SIGPOLL\n"));
}

int socket_initialize(const char *addr, int port)
{
	struct sockaddr_in server;

	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1)
	{
		fprintf(stderr, "Could not create socket\n");
		return 1;
	} else {
		fprintf(stdout, "Socket created: 0x%X\n", socket_fd);
	}

        /* request receipt of SIGPOLL signals */
        signal(SIGIO, SigPoll);

	/* first we must put the socket in asynchronous mode */
	int flag = 1;
        int ret = ioctl(socket_fd, FIOASYNC, &flag);
        if (ret < 0) {
                fprintf(stderr, "ioctl error. sd=%d, ret=%d, errno=%d\n",
                                socket_fd, ret, errno);
                return 1;
        }

	 /* next, set the *socket's* process group.  This is stored in the
         * socket structure (<sys/net/socketvar.h> so_pgrp) and all processes
         * part of this socket process group will receive SIGPOLL when
         * data is received (of course assuming socket is in async. mode)
         */
        pid_t pid = getpid(); /* this system call never fails */
        ret = ioctl(socket_fd, SIOCSPGRP, &pid);
        if (ret < 0) {
                fprintf(stderr, "ioctl error2 sd=%d, ret=%d, errno=%d\n",
                                socket_fd, ret, errno);
                return 1;
        }

	server.sin_addr.s_addr = inet_addr(addr);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if (connect(socket_fd, (struct sockaddr *) &server , sizeof(server)) < 0)
	{
		fprintf(stderr, "Connect to %s:%d failed\n", addr, port);
		return 1;
	}

	fprintf(stdout, "Connected to %s:%d\n", addr, port);
	
	return 0;
}

void signalHandler( int signum )
{
   fprintf(stderr, "Interrupt signal %d received\n", signum);

   close(socket_fd);
   remove_inotify_watch(inotify_fd);

   exit(signum);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signalHandler);

    inotify_initialize();
    socket_initialize(argv[1], atoi(argv[2]));
    
    int events = IN_MODIFY | IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_DONT_FOLLOW;

    watch(argv[3], events);

    close(socket_fd);
    remove_inotify_watch(inotify_fd);	
    
    return EXIT_SUCCESS;
}
