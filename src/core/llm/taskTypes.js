/**
 * Standard Task Types for LLM Task-Based Routing
 */

export const TaskTypes = {
    REPOSITORY_SUMMARY: 'repository_summary',
    TOOL_OUTPUT_NORMALIZATION: 'tool_output_normalization',
    CWE_CLASSIFICATION: 'cwe_classification',
    CODE_REASONING: 'code_reasoning',
    HYPOTHESIS_FORMULATION: 'hypothesis_formulation',
    INVARIANT_GENERATION: 'invariant_generation',
    HARNESS_GENERATION: 'harness_generation',
    CROSS_FILE_REASONING: 'cross_file_reasoning',
    VERIFICATION: 'verification',
    NOVELTY_ANALYSIS: 'novelty_analysis',
    REPORT_GENERATION: 'report_generation'
};

export const TASK_PROFILES = {
    [TaskTypes.REPOSITORY_SUMMARY]: {
        priority: 'low',
        requiresReasoning: false,
        requiresCode: false,
        costPreference: 'low',
        isExploratory: false
    },
    [TaskTypes.TOOL_OUTPUT_NORMALIZATION]: {
        priority: 'low',
        requiresReasoning: false,
        requiresCode: false,
        costPreference: 'low',
        isExploratory: false
    },
    [TaskTypes.CWE_CLASSIFICATION]: {
        priority: 'medium',
        requiresReasoning: true,
        requiresCode: true,
        costPreference: 'medium',
        isExploratory: false
    },
    [TaskTypes.CODE_REASONING]: {
        priority: 'high',
        requiresReasoning: true,
        requiresCode: true,
        costPreference: 'medium',
        isExploratory: false
    },
    [TaskTypes.HYPOTHESIS_FORMULATION]: {
        priority: 'high',
        requiresReasoning: true,
        requiresCode: true,
        costPreference: 'medium',
        isExploratory: true
    },
    [TaskTypes.INVARIANT_GENERATION]: {
        priority: 'high',
        requiresReasoning: true,
        requiresCode: true,
        costPreference: 'high',
        isExploratory: true
    },
    [TaskTypes.HARNESS_GENERATION]: {
        priority: 'high',
        requiresReasoning: true,
        requiresCode: true,
        costPreference: 'medium',
        isExploratory: false
    },
    [TaskTypes.CROSS_FILE_REASONING]: {
        priority: 'high',
        requiresReasoning: true,
        requiresCode: true,
        costPreference: 'high',
        isExploratory: true
    },
    [TaskTypes.VERIFICATION]: {
        priority: 'critical',
        requiresReasoning: true,
        requiresCode: true,
        costPreference: 'high',
        isExploratory: false
    },
    [TaskTypes.NOVELTY_ANALYSIS]: {
        priority: 'high',
        requiresReasoning: true,
        requiresCode: true,
        costPreference: 'high',
        isExploratory: true
    },
    [TaskTypes.REPORT_GENERATION]: {
        priority: 'medium',
        requiresReasoning: false,
        requiresCode: false,
        costPreference: 'low',
        isExploratory: false
    }
};
