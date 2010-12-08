package com.ubuntu.apport;

/*
 * Apport handler for uncaught Java exceptions
 * 
 * Copyright: 2010 Canonical Ltd.
 * Author: Matt Zimmerman <mdz@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
 * the full text of the license.
 */

import java.io.*;
import java.util.HashMap;

public class ApportUncaughtExceptionHandler
	implements java.lang.Thread.UncaughtExceptionHandler {

	/* Write out an apport problem report with details of the
     * exception, then print it in the usual canonical format */
	public void uncaughtException(Thread t, Throwable e) {
		//System.out.println("uncaughtException");
		if (e instanceof ThreadDeath)
			return;

		HashMap problemReport = getProblemReport(t, e);
		//System.out.println("got problem report");

		try {
			String handler_path = System.getenv("APPORT_JAVA_EXCEPTION_HANDLER");
			if (handler_path == null)
			    handler_path = "/usr/share/apport/java_uncaught_exception";
		 	Process p = new ProcessBuilder(handler_path).start();
			//System.out.println("started process");

			OutputStream os = p.getOutputStream();
			writeProblemReport(os, problemReport);
			//System.out.println("wrote problem report");

			os.close();

			try {
				p.waitFor();
			} catch (InterruptedException ignore) {
				// ignored
			}

		} catch (java.io.IOException ioe) {
		    System.out.println("could not call java_uncaught_exception");
		}

        System.err.print("Exception in thread \""
                         + t.getName() + "\" ");
        e.printStackTrace(System.err);
	}

	public HashMap getProblemReport(Thread t, Throwable e) {
		HashMap problemReport = new HashMap();
		
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);
		problemReport.put("StackTrace", sw.toString());

		problemReport.put("MainClassUrl", mainClassUrl(e));

		return problemReport;
	}

	public void writeProblemReport(OutputStream os, HashMap pr)
		throws IOException {

		StringWriter sw = new StringWriter();
		for(Object o : pr.keySet()) {
			String key = (String)o;
			String value = (String)pr.get(o);
			sw.write(key);
			sw.write("\0");
			sw.write(value);
			sw.write("\0");
		}
		os.write(sw.toString().getBytes());
	}

	public static String mainClassUrl(Throwable e) {
		StackTraceElement[] stacktrace = e.getStackTrace();
		String className = stacktrace[stacktrace.length-1].getClassName();

		if (!className.startsWith("/")) {
			className = "/" + className;
		}
		className = className.replace('.', '/');
		className = className + ".class";

		java.net.URL classUrl =
			new ApportUncaughtExceptionHandler().getClass().getResource(className);

		return classUrl.toString();
    }

	/* Install this handler as the default uncaught exception handler */
	public static void install() {
		Thread.setDefaultUncaughtExceptionHandler(new ApportUncaughtExceptionHandler());
	}
}
