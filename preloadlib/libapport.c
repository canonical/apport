/**
 * @file libapport.c
 * Installs a signal handler for SIGILL, SIGFPE and SIGSEGV and
 * calls 'AGENTPATH <signal> <pid> <core dump>' upon them.
 * This library can either be linked to a program or used with
 * LD_PRELOAD=libapport.so.
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
#include <stdlib.h>
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
    char corepath[PATH_MAX];
    char *core = NULL;
    int status;

    // generate core file
    pid_t pid = fork();
    if( pid == 0 ) {
	if( execl( "/usr/bin/gcore", "/usr/bin/gcore", "-o", "core", spid, NULL ) == -1 )
	    perror( "Error: could not execute gcore" );
	goto out;
    }

    snprintf( corepath, sizeof(corepath), "%s.%s", "core", spid );

    wait( &status );

    /* only pass the core file if gcore succeeded */
    if( WIFEXITED( status ) && WEXITSTATUS( status ) == 0 )
	core = corepath;

    pid = fork();
    if( pid == 0 ) {
	if( execl( AGENTPATH, AGENTPATH, spid, ssig, core, NULL ) == -1 )
	    perror( "Error: could not execute " AGENTPATH );
	goto out;
    }

    wait( &status );

out:
    unlink( corepath );
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
