/**
 * @file libapport.c
 * Installs a signal handler for SIGILL, SIGFPE and SIGSEGV and
 * calls 'AGENTPATH <signal> <pid> <core dump>' upon them.
 * This library can either be linked to a program or used with
 * LD_PRELOAD=libapport.so.
 * 
 * If PIPE_CORE is defined, the core dump is piped to the agent's STDIN
 * (similar to the pipe-in-core_pattern feature of Linux 2.6.19), otherwise the
 * path is passed to the agent and the REMOVE_CORE environment variable is set.
 *
 * Copyright (c) 2006 Canonical Ltd.
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
#include <sys/wait.h>
#include <unistd.h>

#ifndef AGENTPATH
#error AGENTPATH must be defined
#endif

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

#ifdef PIPE_CORE
    strcpy( corepath, "/tmp/core.XXXXXX" );
    status = mkstemp( corepath );
    if( status < 0 ) {
        perror( "mkstemp" );
        goto out;
    }
    close( status );
#else
    snprintf( corepath, sizeof(corepath), "core.%s", spid );
#endif

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
#ifndef PIPE_CORE
        setenv("REMOVE_CORE", "1", 1);
#endif
    }

    pid = fork();
    if( pid == 0 ) {
        int devnull = open( "/dev/null", O_WRONLY );
#ifdef PIPE_CORE
        int corepipe;
        if( core ) {
            corepipe = open( corepath, O_RDONLY );
            unlink( corepath );
            if( corepipe > 0 ) {
                dup2( corepipe, 0 );
                core = "-";
            }
        }
#endif
        if( devnull > 0 )
            dup2(devnull, 2);
        if( execl( AGENTPATH, AGENTPATH, spid, ssig, core, NULL ) == -1 )
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
    /* install signal handler */
    struct sigaction sa;
    sa.sa_handler = sighandler;
    sigemptyset( &sa.sa_mask );
    sa.sa_flags = SA_RESETHAND;
    if( sigaction( SIGILL, &sa, NULL ) == -1 ||
            sigaction( SIGFPE, &sa, NULL ) == -1 ||
            sigaction( SIGSEGV, &sa, NULL ) == -1 )
        perror( "Could not set signal handler" );
}
