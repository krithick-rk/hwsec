package org.owasp.benchmark.harness;

import java.util.*;

/**
 * SecuritySinkObserver
 * 
 * Non-permissive observer that records security-relevant operations
 * without fabricating proofs or simulating vulnerabilities.
 */
public class SecuritySinkObserver {
    public static class SinkEvent {
        public String sinkType;
        public String targetMethod;
        public String argumentValue;
        public long timestamp;

        public SinkEvent(String sinkType, String targetMethod, String argumentValue) {
            this.sinkType = sinkType;
            this.targetMethod = targetMethod;
            this.argumentValue = argumentValue;
            this.timestamp = System.currentTimeMillis();
        }
    }

    private static final List<SinkEvent> events = Collections.synchronizedList(new ArrayList<>());

    public static void recordSinkCall(String sinkType, String targetMethod, String argumentValue) {
        events.add(new SinkEvent(sinkType, targetMethod, argumentValue));
    }

    public static List<SinkEvent> getEvents() {
        return new ArrayList<>(events);
    }

    public static void clear() {
        events.clear();
    }
}
