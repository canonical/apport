import com.ubuntu.apport.*;

class crash {
    public static void main(String[] args) {
        com.ubuntu.apport.ApportUncaughtExceptionHandler.install();
        throw new RuntimeException("Can't catch this");
    }
}
