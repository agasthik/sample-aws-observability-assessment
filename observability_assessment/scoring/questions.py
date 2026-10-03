# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Assessment question registry: definitions, maturity descriptions, and evidence-check mappings."""

from observability_assessment.models import ObservabilityCheck


class QuestionScoringMixin:
    """Scoring methods that operate on ``self.results``."""

    def setup_assessment_questions(self):
        """Setup all 17 assessment questions with maturity levels"""

        # Logs Category (Questions 1-4)
        self.results.assessment_checks.extend(
            [
                ObservabilityCheck(
                    question_id=1,
                    category="Logs",
                    question="How do you collect logs?",
                    maturity_descriptions={
                        1: "Basic log groups exist, some services logging",
                        2: "Logging on at least half of compute types in use, with structured JSON or two or more compute types logging",
                        3: "Logging on at least 75% of compute types in use, structured JSON, and cross-account or cross-Region centralization",
                        4: "Level 3 plus the EKS CloudWatch Observability add-on or log anomaly detection",
                    },
                ),
                ObservabilityCheck(
                    question_id=2,
                    category="Logs",
                    question="How do you use logs?",
                    maturity_descriptions={
                        1: "Manual log searches and basic queries",
                        2: "Structured queries with faster analysis",
                        3: "Automated correlation and anomaly detection",
                        4: "Automated resolution and MTTR reduction",
                    },
                ),
                ObservabilityCheck(
                    question_id=3,
                    category="Logs",
                    question="How do you access logs?",
                    maturity_descriptions={
                        1: "Basic centralized collection",
                        2: "Enterprise-wide visibility with prioritization",
                        3: "Single-pane correlation and anomaly detection",
                        4: "Automated insights with proactive root cause",
                    },
                ),
                ObservabilityCheck(
                    question_id=4,
                    category="Logs",
                    question="What is your log retention policy?",
                    maturity_descriptions={
                        1: "Disparate retention policies",
                        2: "Enterprise-wide compliance-based policies",
                        3: "Automated archival with cost optimization",
                        4: "Easy retrieval with metadata-based search",
                    },
                ),
            ]
        )

        # Metrics Category (Questions 5-7)
        self.results.assessment_checks.extend(
            [
                ObservabilityCheck(
                    question_id=5,
                    category="Metrics",
                    question="What type of metrics do you collect?",
                    maturity_descriptions={
                        1: "Infrastructure metrics only (CPU, memory, disk utilization)",
                        2: "Infrastructure and application metrics (latency, errors, volume)",
                        3: "Infrastructure, application, and custom metrics",
                        4: "All metrics with dimensions for critical metadata",
                    },
                ),
                ObservabilityCheck(
                    question_id=6,
                    category="Metrics",
                    question="How do you use metrics?",
                    maturity_descriptions={
                        1: "Manually explore metrics when diagnosing issues",
                        2: "Dashboards and alerting for manual reaction",
                        3: "Infrastructure automation and operational reviews",
                        4: "AI/ML capabilities for proactive issue identification",
                    },
                ),
                ObservabilityCheck(
                    question_id=7,
                    category="Metrics",
                    question="How do you access metrics?",
                    maturity_descriptions={
                        1: "Centralized metric collection mechanism",
                        2: "Enterprise-wide visibility for analysis and troubleshooting",
                        3: "Correlation and anomaly detection for root cause",
                        4: "Automated insights with proactive resolution options",
                    },
                ),
            ]
        )

        # Traces Category (Questions 8-9)
        self.results.assessment_checks.extend(
            [
                ObservabilityCheck(
                    question_id=8,
                    category="Traces",
                    question="How do you collect traces?",
                    maturity_descriptions={
                        1: "Auto-instrumented SDKs for monitoring",
                        2: "Auto + manual instrumentation",
                        3: "End-to-end visibility with correlation",
                        4: "Automatic injection with proactive alerts",
                    },
                ),
                ObservabilityCheck(
                    question_id=9,
                    category="Traces",
                    question="How do you use traces?",
                    maturity_descriptions={
                        1: "Centralized trace collection mechanism",
                        2: "Analyze and troubleshoot issues based on captured information",
                        3: "360-degree view for correlation and anomaly detection",
                        4: "Cross-boundary insights with proactive root cause identification",
                    },
                ),
            ]
        )

        # Dashboards & Alerting Category (Questions 10-12)
        self.results.assessment_checks.extend(
            [
                ObservabilityCheck(
                    question_id=10,
                    category="Dashboards & Alerting",
                    question="How do you use alarms?",
                    maturity_descriptions={
                        1: "Alarms with notifications when metrics meet triggers",
                        2: "Clear priority for alerts with urgency and customer impact",
                        3: "Actionable alarms based on anomaly detection",
                        4: "Composite alarms for aggregated health indicators",
                    },
                ),
                ObservabilityCheck(
                    question_id=11,
                    category="Dashboards & Alerting",
                    question="How do you use dashboards?",
                    maturity_descriptions={
                        1: "Basic resource monitoring",
                        2: "Single pane of glass with visibility into various data sources",
                        3: "Flexible dashboards with dynamic content based on input fields",
                        4: "Automatically created dynamic visualizations relevant to issues",
                    },
                ),
                ObservabilityCheck(
                    question_id=12,
                    category="Dashboards & Alerting",
                    question="How adaptive are your alarm thresholds?",
                    maturity_descriptions={
                        1: "Alarms triggered immediately when a metric exceeds a static threshold",
                        2: "Alarms triggered when a metric exceeds a threshold for a period of time",
                        3: "Alarms triggered when a metric exhibits anomalous behavior",
                        4: "Continuously analyze metrics, determine baselines, surface anomalies",
                    },
                ),
            ]
        )

        # Organization Category (Questions 13-17)
        self.results.assessment_checks.extend(
            [
                ObservabilityCheck(
                    question_id=13,
                    category="Organization",
                    question="How do you use SLOs?",
                    maturity_descriptions={
                        1: "Team experimentation without adoption",
                        2: "Enterprise adoption for reliability",
                        3: "Prioritization for users and business",
                        4: "Integrated platforms with error budgets",
                    },
                ),
                ObservabilityCheck(
                    question_id=14,
                    category="Organization",
                    question="Do you use any AI/ML capability today?",
                    maturity_descriptions={
                        1: "No AI/ML features",
                        2: "Natural language query capability",
                        3: "Automatic correlation and patterns",
                        4: "Comprehensive AI/ML with real-time insights",
                    },
                ),
                ObservabilityCheck(
                    question_id=15,
                    category="Organization",
                    question="Do you have real end-user monitoring?",
                    maturity_descriptions={
                        1: "Test users for validation",
                        2: "Synthetic scripts on a schedule",
                        3: "Scripted interaction tests with correlation",
                        4: "Real user monitoring with proactive anomalies",
                    },
                ),
                ObservabilityCheck(
                    question_id=16,
                    category="Organization",
                    question="Do you have an enterprise observability strategy?",
                    maturity_descriptions={
                        1: "Data collection strategy only",
                        2: "Unified tools and technologies",
                        3: "Established practices and training",
                        4: "Culture of continuous improvement",
                    },
                ),
                ObservabilityCheck(
                    question_id=17,
                    category="Organization",
                    question="Are you getting ROI from your observability tools?",
                    maturity_descriptions={
                        1: "Want optimization without knowledge",
                        2: "Vendor consolidation attempts",
                        3: "Established validation policies",
                        4: "Business value and cost optimization",
                    },
                ),
            ]
        )

    def get_discovery_checks_for_question(self, question_id: int) -> list:
        """Return discovery check names needed for a given assessment question."""
        mapping = {
            1: [  # How do you collect logs?
                "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)?",
                "What percentage of EC2 instances have the CloudWatch agent installed with both system metrics AND application logs configured?",
                "What percentage of Lambda functions use JSON structured logging?",
                "What percentage of ECS tasks use structured logging (JSON)?",
                "Are all five EKS control plane log types enabled (api, audit, authenticator, controllerManager, scheduler)?",
                "Is the EKS CloudWatch Observability add-on deployed with Container Insights and Application Signals enabled?",
                "What percentage of application logs use structured JSON format for easier parsing and analysis?",
                "Have you implemented cross-account and cross-Region log centralization?",
                "Are you using CloudWatch cross-account observability?",
                "Have you enabled anomaly detection?",
            ],
            2: [  # How do you use logs?
                "Do you have standardized Logs Insights queries for common troubleshooting scenarios (errors, latency, security events)?",
                "Have you created metric filters to extract KPIs from logs?",
                "Have you enabled anomaly detection?",
                "What percentage of application logs use structured JSON format for easier parsing and analysis?",
                "What percentage of Lambda functions use JSON structured logging?",
                "What percentage of ECS tasks use structured logging (JSON)?",
                "Do you have field index policies configured for faster log queries?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
                "Do you have stale or unused log groups that are collecting data but not being used?",
            ],
            3: [  # How do you access logs?
                "What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)?",
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "What percentage of the largest log groups have subscription filters for real-time processing?",
                "Have you implemented cross-account and cross-Region log centralization?",
                "Are you using CloudWatch cross-account observability?",
                "Have you enabled anomaly detection?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
                "Have you configured CloudWatch Investigations actions for any alarms?",
                "Do you use CloudWatch Omni spaces for unified access to logs, metrics, and traces?",
            ],
            4: [  # What is your log retention policy?
                "What percentage of the largest log groups have retention policies configured (example thresholds: security: 90+ days, operational: 30 days, debug: 7 days — actual requirements vary by organization)?",
                "Do you have log export tasks configured for archival?",
                "What percentage of the largest log groups have subscription filters for real-time processing?",
                "Have you implemented cross-account and cross-Region log centralization?",
                "Do your log groups have resource tags for retention governance and metadata-based search?",
                "Do you have stale or unused log groups that are collecting data but not being used?",
            ],
            5: [  # What type of metrics do you collect?
                "Are you publishing custom business and application metrics to CloudWatch?",
                "What percentage of production EC2 instances have detailed monitoring (1-minute metrics) enabled?",
                "How many ECS clusters are available to monitor?",
                "Do you have ECS clusters with Container Insights enabled?",
                "Do you have EKS clusters with the CloudWatch Observability add-on enabled?",
                "What percentage of Lambda functions have Lambda Insights enabled for enhanced metrics?",
                "Is the CloudWatch agent configured to collect system-level metrics?",
                "Do you use CloudWatch Application Signals to monitor application services?",
            ],
            6: [  # How do you use metrics?
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you have CloudWatch alarms configured for your resources?",
                "Do you use anomaly detection models for adaptive alarming?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
            ],
            7: [  # How do you access metrics?
                "Have you configured metric streams for real-time export to third-party tools or data lakes?",
                "Are you using CloudWatch cross-account observability?",
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you use anomaly detection models for adaptive alarming?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
                "Do you use CloudWatch Omni spaces for unified access to logs, metrics, and traces?",
            ],
            8: [  # How do you collect traces?
                "Do you use X-Ray service maps to visualize application architecture?",
                "Do your Lambda functions have X-Ray tracing enabled?",
                "Do you have custom X-Ray sampling rules configured?",
                "Do you have X-Ray groups configured for focused trace analysis?",
                "Do you have Transaction Search enabled?",
                "Do your traces contain custom annotations indicating manual instrumentation?",
            ],
            9: [  # How do you use traces?
                "Do you use X-Ray service maps to visualize application architecture?",
                "Do you have X-Ray Insights configured for anomaly detection?",
                "Do you use CloudWatch Application Signals to monitor application services?",
                "Do you have X-Ray groups configured for focused trace analysis?",
                "Do you have Transaction Search enabled?",
                "Do you use CloudWatch RUM to monitor real user experiences?",
                "Do you use CloudWatch Synthetics to monitor application endpoints?",
                "Have you defined Service Level Objectives (SLOs) for critical application services?",
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you have CloudWatch alarms configured for your resources?",
                "Do you use composite alarms to reduce alarm noise?",
            ],
            10: [  # How do you use alarms?
                "Do you have CloudWatch alarms configured for your resources?",
                "Do you use composite alarms to reduce alarm noise?",
                "Do your alarms send notifications to SNS topics?",
                "Do you use anomaly detection models for adaptive alarming?",
                "Have you configured CloudWatch Investigations actions for any alarms?",
                "Do you have any Systems Manager OpsCenter actions configured with your alarms?",
                "Do you have any Lambda actions configured with your alarms?",
                "Do you have any EC2 actions configured with your alarms?",
            ],
            11: [  # How do you use dashboards?
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you have dashboards configured with variables?",
                "Do you use CloudWatch Application Signals to monitor application services?",
            ],
            12: [  # How adaptive are your alarm thresholds?
                "Do you use anomaly detection models for adaptive alarming?",
                "Do you have CloudWatch alarms configured for your resources?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
                "Have you configured CloudWatch Investigations actions for any alarms?",
            ],
            13: [  # How do you use SLOs?
                "Have you defined Service Level Objectives (SLOs) for critical application services?",
                "Do you use CloudWatch Application Signals to monitor application services?",
                "Do you have CloudWatch alarms configured for your resources?",
            ],
            14: [  # Do you use any AI/ML capability today?
                "Do you use anomaly detection models for adaptive alarming?",
                "Do you use AWS DevOps Agent for AI-assisted troubleshooting?",
                "Have you configured CloudWatch Investigations actions for any alarms?",
                "Have you enabled anomaly detection?",
            ],
            15: [  # Do you have real end-user monitoring?
                "Do you use CloudWatch RUM to monitor real user experiences?",
                "Do you use CloudWatch Synthetics to monitor application endpoints?",
            ],
            16: [  # Do you have an enterprise observability strategy?
                "Do you use resource tags for organizing and managing AWS resources?",
                "Are you using CloudWatch cross-account observability?",
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "What percentage of application logs use structured JSON format for easier parsing and analysis?",
                "Do you use CloudWatch Application Signals to monitor application services?",
                "Have you defined Service Level Objectives (SLOs) for critical application services?",
                "Do you use CloudWatch Omni spaces for unified access to logs, metrics, and traces?",
                "Have you connected CloudWatch Omni integrations (Context Graph resource discovery, Slack, external agents)?",
            ],
            17: [  # Are you getting ROI from your observability tools?
                "Do you have CloudWatch dashboards for visualizing metrics and logs?",
                "Do you have CloudWatch alarms configured for your resources?",
                "What percentage of the largest log groups have retention policies configured (example thresholds: security: 90+ days, operational: 30 days, debug: 7 days — actual requirements vary by organization)?",
                "Do you use resource tags for organizing and managing AWS resources?",
                "Do you have log export tasks configured for archival?",
                "Do you use composite alarms to reduce alarm noise?",
                "Do you have stale or unused log groups that are collecting data but not being used?",
                "Have you defined Service Level Objectives (SLOs) for critical application services?",
            ],
        }
        return mapping.get(question_id, [])
