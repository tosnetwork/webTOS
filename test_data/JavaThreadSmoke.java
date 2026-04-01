import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;

final class JavaThreadSmoke {
    public static void main(String[] args) throws Exception {
        final int threads = 4;
        final int iterations = 20_000;
        final AtomicLong total = new AtomicLong();
        final CountDownLatch done = new CountDownLatch(threads);

        for (int id = 0; id < threads; id++) {
            final int workerId = id;
            Thread thread = new Thread(() -> {
                long local = 0;
                for (int i = 0; i < iterations; i++) {
                    local += (long) (i ^ workerId);
                }
                total.addAndGet(local);
                done.countDown();
            }, "tos-java-" + id);
            thread.start();
        }

        done.await();

        long expected = 0;
        for (int id = 0; id < threads; id++) {
            long local = 0;
            for (int i = 0; i < iterations; i++) {
                local += (long) (i ^ id);
            }
            expected += local;
        }

        long actual = total.get();
        if (actual != expected) {
            System.out.println(
                    "TOS-JAVA-THREAD-FAIL total=" + actual + " expected=" + expected);
            System.exit(1);
        }

        System.out.println("TOS-JAVA-THREAD-OK total=" + actual);
    }
}
