package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @PostMapping("/api/rules/evaluate")
    public String evaluateRule(@RequestBody RuleRequest request) {
        try {
            ExpressionParser parser = new SpelExpressionParser();
            SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
            context.setVariable("user", "admin");
            Expression exp = parser.parseExpression(request.getExpression());
            Object val = exp.getValue(context);
            return val != null ? val.toString() : "null";
        } catch (Exception e) {
            return "Execution Blocked";
        }
    }

    public static class RuleRequest {
        private String expression;
        public String getExpression() { return expression; }
        public void setExpression(String expression) { this.expression = expression; }
    }
}
