/**
 * @file libapport.c
 * Installs a signal handler for SIGILL, SIGFPE, SIGABRT, and SIGSEGV and
 * calls 'AGENTPATH' upon them.
 * This library can either be linked to a program or used with
 * LD_PRELOAD=libapport.so.
 * 
 * The core dump is piped to the agent's STDIN (similar to the
 * pipe-in-core_pattern feature of Linux 2.6.19).
 *
 * Copyright (c) 2007 Canonical Ltd.
 * Author: Martin Pitt <martin.pitt@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
 * the full text of the license.
*/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef AGENTPATH
#error AGENTPATH must be defined
#endif

static int core_limit;

/**
 * setenv() for int values.
 */
void setenv_int(const char* name, int value, int overwrite)
{
    static char buffer[20];
    snprintf(buffer, sizeof(buffer), "%i", value);
    setenv(name, buffer, overwrite);
}

/**
 * Common signal handler. This collects all information, writes them into a
 * temporary file and calls an interactive frontend.
 */
void sighandler( int signum )
{
    char ssig[20], spid[20];
    sprintf( ssig, "%i", signum );
    sprintf( spid, "%i", getpid() );
    char core_arg[PATH_MAX];
    char corepath[PATH_MAX];
    char *core = NULL;
    int status;

    strcpy( corepath, "/tmp/core.XXXXXX" );
    status = mkstemp( corepath );
    if( status < 0 ) {
        perror( "mkstemp" );
        goto out;
    }
    close( status );

    // generate core file
    pid_t pid = fork();
    if( pid < 0 ) {
        perror( "fork" );
        goto out;
    }
    if( pid == 0 ) {
        int devnull = open( "/dev/null", O_WRONLY );
        if( devnull > 0 )
            dup2(devnull, 1);
            dup2(devnull, 2);
        snprintf( core_arg, sizeof( core_arg ), "generate-core-file %s", corepath );
        execl( "/usr/bin/gdb", "/usr/bin/gdb", "--batch", "--ex", core_arg, "--pid", spid, NULL );
        perror( "Error: could not execute gcore" );
        goto out;
    }

    if( wait( &status ) < 0 ) {
        perror( "wait() on gdb" );
        goto out;
    }

    /* only pass the core file if gcore succeeded */
    if( WIFEXITED( status ) && WEXITSTATUS( status ) == 0 ) {

        core = corepath;
	setenv( "CORE_PID", spid, 1 );
	setenv_int( "CORE_UID", getuid(), 1 );
	setenv_int( "CORE_GID", getgid(), 1 );
	setenv( "CORE_SIGNAL", ssig, 1 );
	setenv_int( "CORE_REAL_RLIM", core_limit, 1 );
    }

    pid = fork();
    if( pid == 0 ) {
        int devnull = open( "/dev/null", O_WRONLY );
        int corepipe;
        if( core ) {
            corepipe = open( corepath, O_RDONLY );
            unlink( corepath );
            if( corepipe > 0 )
                dup2( corepipe, 0 );
        }
        if( devnull > 0 )
            dup2(devnull, 2);
        if( execl( AGENTPATH, AGENTPATH, NULL ) == -1 )
            perror( "Error: could not execute " AGENTPATH );
        goto out;
    }

    if( wait( &status ) < 0 ) {
        perror( "wait() on agent" );
        goto out;
    }

out:
    raise( signum );
}

/**
 * Library constructor; this installs the signal handler for all signals that
 * can be regarded as program crash.
 */
__attribute__ ((constructor))
void init()
{
    struct rlimit core_rlim;

    /* get current core limit, we need to pass it to apport */
    if( getrlimit( RLIMIT_CORE, &core_rlim ) < 0 ) {
        perror( "getrlimit(RLIMIT_CORE)" );
        exit(1);
    }
    core_limit = core_rlim.rlim_cur;

    /* disable core rlimit, since we do not want the kernel to produce a core
     * file */
    core_rlim.rlim_cur = 0;
    core_rlim.rlim_max = 0;
    if( setrlimit( RLIMIT_CORE, &core_rlim ) < 0 ) {
        perror( "setrlimit(RLIMIT_CORE)" );
        exit(1);
    }

    /* install signal handler */
    struct sigaction sa;
    sa.sa_handler = sighandler;
    sigemptyset( &sa.sa_mask );
    sa.sa_flags = SA_RESETHAND;
    if( sigaction( SIGILL, &sa, NULL ) == -1 ||
            sigaction( SIGFPE, &sa, NULL ) == -1 ||
            sigaction( SIGABRT, &sa, NULL ) == -1 ||
            sigaction( SIGSEGV, &sa, NULL ) == -1 )
        perror( "Could not set signal handler" );
}
