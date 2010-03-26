package com.ubuntu.apport;

import java.io.*;
import java.util.HashMap;

public class ApportUncaughtExceptionHandler
	implements java.lang.Thread.UncaughtExceptionHandler {

	public void uncaughtException(Thread t, Throwable e) {
		System.out.println("uncaughtException");
		if (e instanceof ThreadDeath)
			return;

		HashMap problemReport = getProblemReport(t, e);
		System.out.println("got problem report");

		try {
		 	Process p = new ProcessBuilder("/usr/share/apport/java_uncaught_exception").start();
			System.out.println("started process");

			OutputStream os = p.getOutputStream();
			writeProblemReport(os, problemReport);
			System.out.println("wrote problem report");

			os.close();

			try {
				p.waitFor();
			} catch (InterruptedException ignore) {
				// ignored
			}

		} catch (java.io.IOException ioe) {
			// ignored
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

	public static void install() {
		Thread.setDefaultUncaughtExceptionHandler(new ApportUncaughtExceptionHandler());
	}
}
