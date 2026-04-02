import java.lang.annotation.Retention;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

final class JavaAnnotationDeadlockProbe {
    @Retention(RUNTIME)
    @AnnB
    public @interface AnnA {}

    @Retention(RUNTIME)
    @AnnA
    public @interface AnnB {}

    static final class Task extends Thread {
        final CountDownLatch prepareLatch;
        final AtomicInteger goLatch;
        final Class<?> clazz;

        Task(CountDownLatch prepareLatch, AtomicInteger goLatch, Class<?> clazz) {
            super(clazz.getSimpleName());
            this.prepareLatch = prepareLatch;
            this.goLatch = goLatch;
            this.clazz = clazz;
            setDaemon(true);
        }

        @Override
        public void run() {
            System.out.println("TOS-JAVA-DEADLOCK-PROBE worker=" + getName() + " stage=prepared");
            prepareLatch.countDown();
            while (goLatch.get() > 0) {
                Thread.onSpinWait();
            }
            System.out.println("TOS-JAVA-DEADLOCK-PROBE worker=" + getName() + " stage=parsing");
            clazz.getDeclaredAnnotations();
            System.out.println("TOS-JAVA-DEADLOCK-PROBE worker=" + getName() + " stage=done");
        }
    }

    private static void dumpThreads(ThreadMXBean bean) {
        System.out.println("TOS-JAVA-DEADLOCK-PROBE stage=thread-dump");
        for (ThreadInfo info : bean.dumpAllThreads(true, true)) {
            System.out.println("TOS-JAVA-DEADLOCK-PROBE dump=" + info.getThreadName()
                    + " state=" + info.getThreadState());
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("TOS-JAVA-DEADLOCK-PROBE stage=start");
        CountDownLatch prepareLatch = new CountDownLatch(2);
        AtomicInteger goLatch = new AtomicInteger(1);
        Task taskA = new Task(prepareLatch, goLatch, AnnA.class);
        Task taskB = new Task(prepareLatch, goLatch, AnnB.class);
        taskA.start();
        taskB.start();

        prepareLatch.await();
        System.out.println("TOS-JAVA-DEADLOCK-PROBE stage=workers-ready");
        goLatch.set(0);
        System.out.println("TOS-JAVA-DEADLOCK-PROBE stage=workers-released");

        ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        for (int attempt = 1; attempt <= 20; attempt++) {
            System.out.println("TOS-JAVA-DEADLOCK-PROBE stage=join-before attempt=" + attempt
                    + " aAlive=" + taskA.isAlive()
                    + " bAlive=" + taskB.isAlive());
            taskA.join(500L);
            taskB.join(500L);
            System.out.println("TOS-JAVA-DEADLOCK-PROBE stage=join-after attempt=" + attempt
                    + " aAlive=" + taskA.isAlive()
                    + " bAlive=" + taskB.isAlive());

            long[] deadlockedIds = threadBean.findMonitorDeadlockedThreads();
            int deadlocked = deadlockedIds == null ? 0 : deadlockedIds.length;
            System.out.println("TOS-JAVA-DEADLOCK-PROBE stage=mxbean attempt=" + attempt
                    + " deadlocked=" + deadlocked);

            if (deadlocked > 0) {
                for (ThreadInfo info : threadBean.getThreadInfo(deadlockedIds, Integer.MAX_VALUE)) {
                    System.out.println("TOS-JAVA-DEADLOCK-PROBE deadlock=" + info);
                }
                System.exit(2);
            }

            if (!taskA.isAlive() && !taskB.isAlive()) {
                System.out.println("TOS-JAVA-DEADLOCK-PROBE OK");
                return;
            }
        }

        dumpThreads(threadBean);
        System.out.println("TOS-JAVA-DEADLOCK-PROBE FAIL");
        System.exit(3);
    }
}
