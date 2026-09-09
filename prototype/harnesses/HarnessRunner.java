package org.owasp.benchmark.harness;

import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HarnessRunner {
    public static void main(String[] args) {
        String caseId = null;
        String inputValue = "";
        String inputType = "PARAMETER";
        String method = "doPost";

        for (int i = 0; i < args.length; i++) {
            if ("--case".equals(args[i]) && i + 1 < args.length) {
                caseId = args[++i];
            } else if ("--input".equals(args[i]) && i + 1 < args.length) {
                inputValue = args[++i];
            } else if ("--b64input".equals(args[i]) && i + 1 < args.length) {
                try {
                    inputValue = new String(java.util.Base64.getDecoder().decode(args[++i]), "UTF-8");
                } catch (Exception e) {
                    inputValue = "";
                }
            } else if ("--type".equals(args[i]) && i + 1 < args.length) {
                inputType = args[++i];
            } else if ("--method".equals(args[i]) && i + 1 < args.length) {
                method = args[++i];
            }
        }

        if (caseId == null) {
            System.err.println("{\"error\": \"Missing --case argument\"}");
            System.exit(1);
        }

        SecuritySinkObserver.clear();
        String className = "org.owasp.benchmark.testcode." + caseId;

        try {
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();

            final String finalInputVal = inputValue;
            final String finalCaseId = caseId;
            final String finalInputType = inputType;
            final String finalMethod = method;

            final StringWriter responseWriter = new StringWriter();
            final PrintWriter printWriter = new PrintWriter(responseWriter);

            HttpServletRequest req = (HttpServletRequest) Proxy.newProxyInstance(
                clazz.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method m, Object[] mArgs) throws Throwable {
                        String name = m.getName();
                        if ("getParameter".equals(name) && mArgs != null && mArgs.length > 0) {
                            return finalInputVal;
                        }
                        if ("getParameterMap".equals(name)) {
                            Map<String, String[]> map = new HashMap<>();
                            map.put(finalCaseId, new String[]{finalInputVal});
                            return map;
                        }
                        if ("getParameterNames".equals(name)) {
                            return Collections.enumeration(Collections.singletonList(finalCaseId));
                        }
                        if ("getParameterValues".equals(name)) {
                            return new String[]{finalInputVal};
                        }
                        if ("getCookies".equals(name)) {
                            return new Cookie[]{new Cookie(finalCaseId, finalInputVal)};
                        }
                        if ("getHeader".equals(name) && mArgs != null && mArgs.length > 0) {
                            return finalInputVal;
                        }
                        if ("getHeaders".equals(name)) {
                            return Collections.enumeration(Collections.singletonList(finalInputVal));
                        }
                        if ("getHeaderNames".equals(name)) {
                            return Collections.enumeration(Collections.singletonList(finalCaseId));
                        }
                        if ("getMethod".equals(name)) {
                            return finalMethod.equalsIgnoreCase("doGet") ? "GET" : "POST";
                        }
                        if ("getRequestURI".equals(name)) {
                            return "/" + finalCaseId;
                        }
                        if ("getRequestURL".equals(name)) {
                            return new StringBuffer("http://localhost:8080/" + finalCaseId);
                        }
                        if ("getQueryString".equals(name)) {
                            return finalCaseId + "=" + finalInputVal;
                        }
                        if ("getCharacterEncoding".equals(name)) {
                            return "UTF-8";
                        }
                        if (m.getReturnType().equals(boolean.class)) return false;
                        if (m.getReturnType().equals(int.class)) return 0;
                        if (m.getReturnType().equals(long.class)) return 0L;
                        return null;
                    }
                }
            );

            HttpServletResponse res = (HttpServletResponse) Proxy.newProxyInstance(
                clazz.getClassLoader(),
                new Class<?>[]{HttpServletResponse.class},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method m, Object[] mArgs) throws Throwable {
                        String name = m.getName();
                        if ("getWriter".equals(name)) {
                            return printWriter;
                        }
                        if (m.getReturnType().equals(boolean.class)) return false;
                        if (m.getReturnType().equals(int.class)) return 200;
                        return null;
                    }
                }
            );

            Method targetMethod = clazz.getMethod(method, HttpServletRequest.class, HttpServletResponse.class);
            targetMethod.setAccessible(true);
            targetMethod.invoke(instance, req, res);

            printWriter.flush();
            String captured = responseWriter.toString();
            List<SecuritySinkObserver.SinkEvent> events = SecuritySinkObserver.getEvents();

            System.out.println("{");
            System.out.println("  \"case_id\": \"" + escapeJson(caseId) + "\",");
            System.out.println("  \"status\": \"SUCCESS\",");
            System.out.println("  \"exit_code\": 0,");
            System.out.println("  \"output_length\": " + captured.length() + ",");
            System.out.println("  \"output_snippet\": \"" + escapeJson(captured.length() > 4000 ? captured.substring(0, 4000) : captured) + "\",");
            System.out.println("  \"sink_events_count\": " + events.size());
            System.out.println("}");
            System.exit(0);

        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            System.out.println("{");
            System.out.println("  \"case_id\": \"" + escapeJson(caseId) + "\",");
            System.out.println("  \"status\": \"EXCEPTION_CAPTURED\",");
            System.out.println("  \"exit_code\": 0,");
            System.out.println("  \"exception_type\": \"" + escapeJson(cause.getClass().getName()) + "\",");
            System.out.println("  \"exception_message\": \"" + escapeJson(cause.getMessage() != null ? cause.getMessage() : "") + "\"");
            System.out.println("}");
            System.exit(0);
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
