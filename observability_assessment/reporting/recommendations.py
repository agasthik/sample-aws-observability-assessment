# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Maturity recommendations for the Cloudscape report."""


class RecommendationReportingMixin:
    def get_recommendations(self, question_id, current_level):
        """Return list of (title, description, url) recommendations for advancing from current_level to current_level+1"""
        recs = {
            1: {  # Q1: How do you collect logs?
                1: [  # L1 → L2
                    (
                        "Install the CloudWatch agent on all EC2 instances",
                        "Deploy the CloudWatch agent across your EC2 fleet using Systems Manager for consistent log and metric collection.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/install-CloudWatch-Agent-on-EC2-Instance.html",
                    ),
                    (
                        "Enable JSON structured logging for Lambda functions",
                        "Set LogFormat to JSON in your Lambda function logging configuration for automatic field discovery in Logs Insights.",
                        "https://docs.aws.amazon.com/lambda/latest/dg/python-logging.html",
                    ),
                    (
                        "Configure ECS task logging with the awslogs driver",
                        "Set up the awslogs log driver in ECS task definitions to send container logs to CloudWatch in a structured format.",
                        "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html",
                    ),
                    (
                        "Enable EKS control plane logging",
                        "Enable all 5 EKS control plane log types: api, audit, authenticator, controllerManager, and scheduler.",
                        "https://docs.aws.amazon.com/prescriptive-guidance/latest/amazon-eks-observability-best-practices/logging-best-practices.html",
                    ),
                    (
                        "Start using CloudWatch Logs Insights for analytics",
                        "Create and save common Logs Insights queries for error patterns, latency analysis, and security events.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Implement cross-account log centralization",
                        "Use CloudWatch Logs Centralization rules to consolidate logs from multiple accounts and regions into a central account.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs_Centralization.html",
                    ),
                    (
                        "Adopt structured JSON logging across all services",
                        "Configure all application logs to use JSON format. Use Powertools for AWS Lambda for zero-effort structured logging.",
                        "https://docs.aws.amazon.com/lambda/latest/dg/python-logging.html",
                    ),
                    (
                        "Set up CloudWatch cross-account observability",
                        "Use Observability Access Manager to give a central monitoring account visibility into log groups across accounts.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Unified-Cross-Account.html",
                    ),
                    (
                        "Simplify log management with CloudWatch Logs Centralization",
                        "Consolidate log data from multiple accounts and regions into a central account, eliminating custom aggregation solutions.",
                        "https://aws.amazon.com/blogs/mt/simplifying-log-management-using-amazon-cloudwatch-logs-centralization/",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Enable CloudWatch log anomaly detection",
                        "Activate anomaly detection on log groups to automatically identify unusual patterns without manual threshold configuration.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/LogsAnomalyDetection.html",
                    ),
                    (
                        "Deploy EKS CloudWatch Observability add-on",
                        "Install the add-on for auto-instrumented collection with Container Insights and Application Signals.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-addon.html",
                    ),
                    (
                        "Implement automated log analysis with AWS DevOps Agent",
                        "Use AWS DevOps Agent for AI-assisted log analysis and troubleshooting to reduce MTTR.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                ],
            },
            2: {  # Q2: How do you use logs?
                1: [  # L1 → L2
                    (
                        "Create metric filters to extract KPIs from logs",
                        "Use CloudWatch metric filters to turn log patterns (error counts, latency values) into CloudWatch metrics you can alarm on.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/MonitoringLogData.html",
                    ),
                    (
                        "Build saved Logs Insights queries for common investigations",
                        "Create and save Logs Insights queries for error analysis, latency percentiles, and top talkers to speed up troubleshooting.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html",
                    ),
                    (
                        "Set up alarms on log-derived metrics",
                        "Create CloudWatch alarms on metric filters so you are notified when error rates or latency thresholds are breached.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Alarm-On-Logs.html",
                    ),
                    (
                        "Extract metric data from your logs",
                        "Identify key operational data locked in logs (slow queries, transaction times, error counts) and publish it as metrics for correlation.",
                        "https://aws-observability.github.io/observability-best-practices/signals/logs/#collect-metric-data-from-your-logs",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Enable log anomaly detection for automated pattern analysis",
                        "Activate CloudWatch log anomaly detectors to automatically identify unusual patterns without manual threshold configuration.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/LogsAnomalyDetection.html",
                    ),
                    (
                        "Use subscription filters for real-time log processing",
                        "Set up subscription filters to stream logs to Lambda or Kinesis for automated correlation, enrichment, and alerting.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions.html",
                    ),
                    (
                        "Leverage Logs Insights PPL and SQL for advanced analytics",
                        "Use OpenSearch PPL/SQL support in Logs Insights for complex joins, correlations, and on-demand anomaly detection across log groups.",
                        "https://aws.amazon.com/blogs/mt/advanced-analytics-using-amazon-cloudwatch-logs-insights/",
                    ),
                    (
                        "Adopt structured logging best practices",
                        "Standardize on JSON structured logging with proper log levels to enable automated filtering, parsing, and anomaly detection.",
                        "https://aws-observability.github.io/observability-best-practices/signals/logs/#structured-logging-is-key-to-success",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Implement automated log analysis with AWS DevOps Agent",
                        "Use AWS DevOps Agent for AI-assisted root cause analysis across logs, metrics, and traces to reduce MTTR.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                    (
                        "Use CloudWatch Investigations for automated correlation",
                        "Enable Investigations to automatically correlate log anomalies with metric and trace signals during incidents.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/investigations.html",
                    ),
                    (
                        "Automate remediation with log-triggered workflows",
                        "Connect log anomaly detections to EventBridge rules and Systems Manager automation runbooks for self-healing responses.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/LogsAnomalyDetection.html",
                    ),
                ],
            },
            3: {  # Q3: How do you access logs?
                1: [  # L1 → L2
                    (
                        "Set up a CloudWatch Omni space for unified log access",
                        "Create a CloudWatch Omni domain and space to query logs alongside metrics and traces in one place, with access controlled per team through space grants.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/omni-set-up-omni.html",
                    ),
                    (
                        "Set up CloudWatch cross-account observability",
                        "Use Observability Access Manager to give a central monitoring account visibility into log groups across all accounts.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Unified-Cross-Account.html",
                    ),
                    (
                        "Implement cross-account log centralization rules",
                        "Use CloudWatch Logs Centralization to consolidate logs from multiple accounts and regions into a central account.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs_Centralization.html",
                    ),
                    (
                        "Create cross-account CloudWatch dashboards with log widgets",
                        "Build dashboards in your monitoring account that include log table and query widgets from source accounts.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html",
                    ),
                    (
                        "Follow cross-account observability best practices",
                        "Set up monitoring and source accounts following the AWS Observability Best Practices guide for enterprise-wide visibility.",
                        "https://aws-observability.github.io/observability-best-practices/guides/cloudwatch_cross_account_observability/",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Enable log anomaly detection on centralized log groups",
                        "Activate anomaly detectors on your centralized log groups to automatically surface unusual patterns across all accounts.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/LogsAnomalyDetection.html",
                    ),
                    (
                        "Build correlation dashboards with logs, metrics, and traces",
                        "Create dashboards that combine log query widgets with metric graphs and trace maps for single-pane correlation.",
                        "https://docs.aws.amazon.com/prescriptive-guidance/latest/implementing-logging-monitoring-cloudwatch/cloudwatch-dashboards-visualizations.html",
                    ),
                    (
                        "Use Logs Insights cross-log-group queries for correlation",
                        "Query across multiple centralized log groups simultaneously to correlate events across services and accounts.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Enable CloudWatch Investigations for automated root cause analysis",
                        "Use Investigations to automatically correlate anomalies across logs, metrics, and traces with AI-assisted root cause identification.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/investigations.html",
                    ),
                    (
                        "Deploy AWS DevOps Agent for proactive insights",
                        "Use AWS DevOps Agent to automatically analyze cross-account observability data and surface actionable insights.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                    (
                        "Automate incident correlation with EventBridge and Systems Manager",
                        "Connect log anomaly detections to Incident Manager for automated incident creation with correlated evidence.",
                        "https://docs.aws.amazon.com/incident-manager/latest/userguide/what-is-incident-manager.html",
                    ),
                ],
            },
            4: {  # Q4: What is your log retention policy?
                1: [  # L1 → L2
                    (
                        "Set consistent retention policies across all log groups",
                        "Configure Amazon CloudWatch Logs retention periods on every log group based on your organization's requirements (e.g., 90, 365, 3653 days).",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html",
                    ),
                    (
                        "Export logs to S3 for long-term archival",
                        "Set up subscription filters or export tasks to send logs to S3 with lifecycle policies for cost-effective long-term storage.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/S3Export.html",
                    ),
                    (
                        "Apply resource tags to log groups for governance",
                        "Tag log groups with compliance, team, and environment metadata to enable policy-based retention management.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html",
                    ),
                    (
                        "Filter logs close to the source to reduce costs",
                        "Reduce log volume by filtering at the source — only ingest what matters to keep costs down and focus on relevant data.",
                        "https://aws-observability.github.io/observability-best-practices/signals/logs/#filter-logs-close-to-the-source",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Implement S3 lifecycle policies with Glacier tiering",
                        "Configure S3 lifecycle rules to transition archived logs to Glacier or Glacier Deep Archive for cost optimization.",
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html",
                    ),
                    (
                        "Use CloudWatch Logs Infrequent Access class for low-query logs",
                        "Move infrequently queried log groups to the Infrequent Access log class for lower ingestion costs.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch_Logs_Log_Classes.html",
                    ),
                    (
                        "Automate retention policy enforcement with AWS Config",
                        "Create AWS Config rules to detect and remediate log groups that don't have compliant retention policies set.",
                        "https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Enable field indexes for metadata-based log search",
                        "Create field indexes on log groups to enable fast, low-cost searches by metadata fields without full log scans.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs-Field-Indexing.html",
                    ),
                    (
                        "Implement tag-based log group discovery and search",
                        "Use resource tags and AWS Resource Explorer to quickly find and query logs by team, service, or compliance tier.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html",
                    ),
                    (
                        "Analyze log usage patterns with the automatic dashboard",
                        "Use the CloudWatch Logs automatic dashboard to understand ingestion patterns and optimize retention and cost.",
                        "https://aws.amazon.com/blogs/mt/analyze-logs-usage-with-amazon-cloudwatch-enhanced-automatic-dashboard/",
                    ),
                ],
            },
            5: {  # Q5: What type of metrics do you collect?
                1: [  # L1 → L2
                    (
                        "Enable Container Insights for ECS and EKS",
                        "Turn on Container Insights to automatically collect application-level metrics like CPU, memory, network, and disk per container.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html",
                    ),
                    (
                        "Enable Lambda Insights for serverless application metrics",
                        "Install the Lambda Insights extension to collect performance metrics like duration, errors, and cold starts.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Lambda-Insights.html",
                    ),
                    (
                        "Publish application metrics using CloudWatch Embedded Metric Format",
                        "Use EMF to emit custom application metrics (latency, error rates, business KPIs) directly from your application logs.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format.html",
                    ),
                    (
                        "Identify and measure your KPIs",
                        "Work backwards from business outcomes to identify which application metrics matter most, then instrument them.",
                        "https://aws-observability.github.io/observability-best-practices/signals/metrics/#know-your-key-performance-indicatorskpis-and-measure-them",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Publish custom metrics with meaningful dimensions",
                        "Add dimensions (environment, service, operation) to custom metrics for granular filtering and troubleshooting.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/publishingMetrics.html",
                    ),
                    (
                        "Enable Application Signals for automatic service metrics",
                        "Use Application Signals to automatically collect latency, error, and fault metrics per service and operation.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals.html",
                    ),
                    (
                        "Correlate operational and business metrics",
                        "Store business metrics alongside operational metrics in CloudWatch so you can correlate infrastructure health with business outcomes.",
                        "https://aws-observability.github.io/observability-best-practices/signals/metrics/#correlate-with-operational-metric-data",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Add custom metrics to Application Signals",
                        "Define application-specific custom metrics in Application Signals for deeper correlation with standard service metrics.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AppSignals-CustomMetrics.html",
                    ),
                    (
                        "Enable detailed monitoring and high-resolution metrics",
                        "Turn on detailed monitoring for EC2 and publish high-resolution custom metrics for sub-minute granularity.",
                        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html",
                    ),
                    (
                        "Use metric math for derived KPIs",
                        "Create metric math expressions to compute derived metrics (availability %, error ratios) directly in CloudWatch.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html",
                    ),
                ],
            },
            6: {  # Q6: How do you use metrics?
                1: [  # L1 → L2
                    (
                        "Create operational dashboards for key services",
                        "Build CloudWatch dashboards with widgets for your most critical service metrics to provide at-a-glance operational visibility.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html",
                    ),
                    (
                        "Set up CloudWatch alarms on critical metrics",
                        "Create alarms for key metrics (CPU, error rates, latency) with SNS notifications so operators can react to issues.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html",
                    ),
                    (
                        "Know what good looks like for your metrics",
                        "Establish healthy baselines for your key metrics so you can set meaningful alarm thresholds.",
                        "https://aws-observability.github.io/observability-best-practices/signals/metrics/#know-what-good-looks-like",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Configure metrics-based auto scaling policies",
                        "Set up target tracking or step scaling policies that use CloudWatch metrics to automatically adjust capacity.",
                        "https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html",
                    ),
                    (
                        "Create alarms using metric math expressions",
                        "Use metric math to create alarms on derived metrics like error percentages or availability ratios.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html",
                    ),
                    (
                        "Conduct regular operational reviews of alarm quality",
                        "Review alarm history to identify noisy alarms, tune thresholds, and ensure a high signal-to-noise ratio.",
                        "https://aws-observability.github.io/observability-best-practices/signals/alarms/#alert-on-things-that-are-actionable",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Enable CloudWatch anomaly detection on key metrics",
                        "Use ML-based anomaly detection to automatically identify unusual metric behavior without manual threshold tuning.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html",
                    ),
                    (
                        "Use anomaly detection algorithms for automated baselining",
                        "Leverage ML to automatically calculate healthy thresholds for metrics where manual baselining is impractical.",
                        "https://aws-observability.github.io/observability-best-practices/signals/metrics/#use-anomaly-detection-algorithms",
                    ),
                    (
                        "Operationalize anomaly detection alarms",
                        "Deploy anomaly detection alarms at scale with proper band tuning to proactively identify issues before customers notice.",
                        "https://aws.amazon.com/blogs/mt/operationalizing-cloudwatch-anomaly-detection/",
                    ),
                ],
            },
            7: {  # Q7: How do you access metrics?
                1: [  # L1 → L2
                    (
                        "Set up a CloudWatch Omni space for unified metric access",
                        "Create a CloudWatch Omni domain and space to query metrics with PromQL alongside logs and traces, with access controlled per team through space grants.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/omni-set-up-omni.html",
                    ),
                    (
                        "Set up CloudWatch cross-account observability for metrics",
                        "Link source accounts to a monitoring account so you can view and query metrics across your organization.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Unified-Cross-Account.html",
                    ),
                    (
                        "Create cross-account dashboards",
                        "Build dashboards in your monitoring account that include metric widgets from multiple source accounts and regions.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html",
                    ),
                    (
                        "Configure metric filters for log-derived metrics",
                        "Create metric filters to extract operational metrics from logs and make them available alongside native CloudWatch metrics.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/MonitoringLogData.html",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Enable CloudWatch Metric Streams for real-time export",
                        "Set up Metric Streams to continuously stream metrics to third-party tools or S3 for advanced correlation and analysis.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Metric-Streams.html",
                    ),
                    (
                        "Use Metrics Insights for cross-account metric queries",
                        "Query and aggregate metrics across accounts using Metrics Insights SQL-like syntax for correlation and anomaly detection.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/query_with_cloudwatch-metrics-insights.html",
                    ),
                    (
                        "Build correlation dashboards combining metrics with logs and traces",
                        "Create dashboards that combine metric graphs, log queries, and trace maps for root cause determination.",
                        "https://docs.aws.amazon.com/prescriptive-guidance/latest/implementing-logging-monitoring-cloudwatch/cloudwatch-dashboards-visualizations.html",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Enable CloudWatch Investigations for automated metric correlation",
                        "Use Investigations to automatically correlate metric anomalies with related logs and traces for proactive root cause identification.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/investigations.html",
                    ),
                    (
                        "Deploy AWS DevOps Agent for AI-assisted metric analysis",
                        "Use AWS DevOps Agent to automatically analyze metric patterns and surface resolution options.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                    (
                        "Use automation and ML for proactive insights",
                        "Leverage ML-based anomaly detection and automation to surface issues before they impact customers.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#use-automation-and-machine-learning",
                    ),
                ],
            },
            8: {  # Q8: How do you collect traces?
                1: [  # L1 → L2
                    (
                        "Migrate from X-Ray SDK to OpenTelemetry instrumentation",
                        "X-Ray SDKs are entering maintenance mode — migrate to OpenTelemetry for broader library support and future-proof instrumentation.",
                        "https://docs.aws.amazon.com/xray/latest/devguide/xray-sdk-migration.html",
                    ),
                    (
                        "Add custom annotations and metadata to traces",
                        "Enrich traces with business context (customer ID, order ID, environment) to enable targeted debugging and search.",
                        "https://aws-observability.github.io/observability-best-practices/signals/traces/#metadata-annotations-and-labels-are-your-best-friend",
                    ),
                    (
                        "Configure X-Ray sampling rules for cost-effective tracing",
                        "Set up sampling rules to control trace volume while ensuring critical transactions are always captured.",
                        "https://docs.aws.amazon.com/xray/latest/devguide/xray-console-sampling.html",
                    ),
                    (
                        "Instrument all integration points between services",
                        "Ensure every service-to-service call is instrumented to emit traces for complete end-to-end visibility.",
                        "https://aws-observability.github.io/observability-best-practices/signals/traces/#instrument-all-of-your-integration-points",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Enable Transaction Search for full-fidelity trace storage",
                        "Turn on Transaction Search to store and query 100% of traces for deep analysis without sampling limitations.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Transaction-Search.html",
                    ),
                    (
                        "Enable Application Signals for automatic service-level tracing",
                        "Use Application Signals to automatically discover services, operations, and dependencies from trace data.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals.html",
                    ),
                    (
                        "Correlate traces with logs and metrics on dashboards",
                        "Build dashboards that combine trace service maps with metric graphs and log queries for 360-degree visibility.",
                        "https://docs.aws.amazon.com/prescriptive-guidance/latest/implementing-logging-monitoring-cloudwatch/cloudwatch-dashboards-visualizations.html",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Deploy CloudWatch Observability EKS add-on for automatic injection",
                        "Install the EKS add-on for zero-code auto-instrumentation with Application Signals and Container Insights.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-addon.html",
                    ),
                    (
                        "Configure X-Ray Insights for proactive anomaly alerts",
                        "Enable X-Ray Insights notifications to automatically detect latency spikes and error rate anomalies.",
                        "https://docs.aws.amazon.com/xray/latest/devguide/xray-console-insights.html",
                    ),
                    (
                        "Use AWS DevOps Agent for AI-assisted trace analysis",
                        "Leverage AWS DevOps Agent to automatically analyze trace patterns and identify cross-service root causes.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                ],
            },
            9: {  # Q9: How do you use traces?
                1: [  # L1 → L2
                    (
                        "Create alarms on X-Ray-derived error rate and latency metrics",
                        "Set up CloudWatch alarms on trace-derived metrics to detect latency spikes and error rate increases.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html",
                    ),
                    (
                        "Enable X-Ray tracing on CloudWatch Synthetics canaries",
                        "Turn on X-Ray tracing for synthetic canaries to correlate synthetic test failures with backend trace data.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries.html",
                    ),
                    (
                        "Measure transaction times and status codes",
                        "Record response times and status codes for every service interaction to track SLA compliance and workload health.",
                        "https://aws-observability.github.io/observability-best-practices/signals/traces/#transaction-time-and-status-matters-so-measure-it",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Define SLOs using Application Signals",
                        "Create Service Level Objectives on Application Signals services to track reliability against business targets.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals-SLOs.html",
                    ),
                    (
                        "Build combined metric and trace dashboards",
                        "Create dashboards with both metric widgets and trace query widgets for correlated troubleshooting.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html",
                    ),
                    (
                        "Create composite alarms combining trace and metric signals",
                        "Use composite alarms to combine X-Ray error rates with CloudWatch metric alarms for holistic health indicators.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-combining.html",
                    ),
                    (
                        "Enable RUM with X-Ray for end-to-end user journey tracing",
                        "Connect CloudWatch RUM to X-Ray to trace requests from the browser through your backend services.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM.html",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Enable CloudWatch Investigations for cross-service trace correlation",
                        "Use Investigations to automatically correlate trace anomalies across service boundaries with AI-assisted analysis.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/investigations.html",
                    ),
                    (
                        "Configure EventBridge rules for X-Ray Insights events",
                        "Set up EventBridge rules that trigger automated workflows when X-Ray detects anomalous trace patterns.",
                        "https://docs.aws.amazon.com/xray/latest/devguide/xray-console-insights.html",
                    ),
                    (
                        "Use AWS DevOps Agent for proactive cross-boundary root cause identification",
                        "Leverage AI-assisted analysis to automatically identify root causes that span multiple services and accounts.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                ],
            },
            10: {  # Q10: How do you use alarms?
                1: [  # L1 → L2
                    (
                        "Add priority indicators to alarm names and descriptions",
                        "Include severity levels (P1/Critical, P2/High, P3/Low) in alarm names and customer impact context in descriptions.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html",
                    ),
                    (
                        "Create severity-based SNS topics for alarm routing",
                        "Set up separate SNS topics by severity (critical, high, low) to route alarms to appropriate notification channels.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html",
                    ),
                    (
                        "Enable recommended alarms for EC2, ECS, EKS, and RDS",
                        "Deploy the CloudWatch recommended alarm configurations for your compute and database resources.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Best_Practices_Recommended_Alarms.html",
                    ),
                    (
                        "Alert only on actionable conditions",
                        "Reduce alarm fatigue by ensuring every alarm triggers a specific action — remove notifications from non-actionable alarms.",
                        "https://aws-observability.github.io/observability-best-practices/signals/alarms/#alert-on-things-that-are-actionable",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Create anomaly detection alarms on key metrics",
                        "Use ML-based anomaly detection alarms that automatically adapt to hourly, daily, and weekly metric patterns.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html",
                    ),
                    (
                        "Set up alarms using metric math expressions",
                        "Create alarms on derived metrics (error percentages, availability ratios) using metric math for more meaningful alerting.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html",
                    ),
                    (
                        "Connect alarms to Systems Manager Incident Manager",
                        "Configure critical alarms to automatically create incidents in Incident Manager for structured incident response.",
                        "https://docs.aws.amazon.com/incident-manager/latest/userguide/what-is-incident-manager.html",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Implement composite alarms for aggregated health indicators",
                        "Combine multiple alarms into composite alarms to create summarized application health indicators and reduce alarm noise.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-combining.html",
                    ),
                    (
                        "Fight alarm fatigue with aggregation",
                        "Distill alerts into aggregates so operators see the root cause, not six symptoms — making runbooks and automation easier.",
                        "https://aws-observability.github.io/observability-best-practices/signals/alarms/#fight-alarm-fatigue-with-aggregation",
                    ),
                    (
                        "Connect alarms to CloudWatch Investigations",
                        "Configure alarms to trigger Investigations for automated AI-assisted root cause analysis when they fire.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/investigations.html",
                    ),
                ],
            },
            11: {  # Q11: How do you use dashboards?
                1: [  # L1 → L2
                    (
                        "Build service-level dashboards with multiple signal types",
                        "Create dashboards that combine metric graphs, log query widgets, and alarm status for a single-pane-of-glass view.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html",
                    ),
                    (
                        "Create cross-account cross-region dashboards",
                        "Build dashboards in your monitoring account that pull metrics and alarms from multiple accounts and regions.",
                        "https://docs.aws.amazon.com/prescriptive-guidance/latest/implementing-logging-monitoring-cloudwatch/cloudwatch-dashboards-visualizations.html",
                    ),
                    (
                        "Communicate status through dashboards",
                        "Use dashboards as the primary communication tool during operational events for faster team coordination.",
                        "https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_event_response_dashboards.html",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Add dashboard variables for flexible filtering",
                        "Create parameterized dashboards with variables so operators can quickly switch between services, environments, or regions.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_dashboard_variables.html",
                    ),
                    (
                        "Add custom widgets for dynamic content",
                        "Use Lambda-backed custom widgets to display dynamic, context-specific information on dashboards.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/add_custom_widget_dashboard.html",
                    ),
                    (
                        "Include correlation widgets combining logs and metrics",
                        "Add log query widgets alongside metric graphs on the same dashboard for faster anomaly correlation.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Use CloudWatch Investigations for auto-generated visualizations",
                        "Enable Investigations to automatically create dynamic dashboards focused only on data relevant to the current issue.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/investigations.html",
                    ),
                    (
                        "Leverage Application Signals auto-generated dashboards",
                        "Use Application Signals pre-built service dashboards that automatically show relevant metrics, traces, and dependencies.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals.html",
                    ),
                    (
                        "Use AWS DevOps Agent for context-aware dashboard generation",
                        "Leverage AI to automatically surface the most relevant visualizations during troubleshooting sessions.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                ],
            },
            12: {  # Q12: How adaptive are your alarm thresholds?
                1: [  # L1 → L2
                    (
                        "Configure time-based alarm evaluation periods",
                        "Set alarms to require multiple evaluation periods or datapoints before triggering to reduce false positives.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html",
                    ),
                    (
                        "Use M out of N alarm evaluation",
                        "Configure alarms to trigger only when M out of N consecutive datapoints breach the threshold for more reliable alerting.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html",
                    ),
                    (
                        "Know what good looks like before setting thresholds",
                        "Establish healthy baselines through load testing or observation before configuring static alarm thresholds.",
                        "https://aws-observability.github.io/observability-best-practices/signals/metrics/#know-what-good-looks-like",
                    ),
                ],
                2: [  # L2 → L3
                    (
                        "Enable anomaly detection alarms",
                        "Replace static thresholds with ML-based anomaly detection that automatically adapts to seasonal and trend patterns.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html",
                    ),
                    (
                        "Operationalize anomaly detection at scale",
                        "Deploy anomaly detection alarms across your fleet with proper band tuning for reliable automated baselining.",
                        "https://aws.amazon.com/blogs/mt/operationalizing-cloudwatch-anomaly-detection/",
                    ),
                    (
                        "Use anomaly detection for metrics where manual baselining is impractical",
                        "Apply ML algorithms to automatically calculate thresholds for the hundreds of metrics in complex distributed systems.",
                        "https://aws-observability.github.io/observability-best-practices/signals/metrics/#use-anomaly-detection-algorithms",
                    ),
                ],
                3: [  # L3 → L4
                    (
                        "Enable AWS DevOps Agent for continuous metric analysis",
                        "Use AI to continuously analyze metrics, determine normal baselines, and surface anomalies with minimal intervention.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                    (
                        "Use CloudWatch Investigations for automated anomaly correlation",
                        "Enable Investigations to automatically correlate anomaly detection alerts with related signals across your environment.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/investigations.html",
                    ),
                    (
                        "Combine anomaly detection with composite alarms",
                        "Create composite alarms that aggregate anomaly detection alarms for application-level health indicators that account for seasonality.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-combining.html",
                    ),
                ],
            },
            16: {  # Q16: Do you have an enterprise observability strategy?
                1: [  # L1 → L2: data collection only → unified tools and technologies
                    (
                        "Create a CloudWatch Omni organization domain",
                        "Create an Omni organization domain from the management account so every member account can create a linked space under a single sign-in URL and identity provider.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/omni-set-up-omni-for-your-organization.html",
                    ),
                    (
                        "Standardize on a common observability toolset across teams",
                        "Adopt a unified set of tools across all teams to reduce operational friction, training overhead, and time-to-resolution.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#every-workload-is-different-but-common-tools-make-for-a-faster-results",
                    ),
                    (
                        "Implement a consistent resource tagging strategy",
                        "Define and enforce mandatory tags (team, environment, service, cost-center) across all AWS resources for observability governance.",
                        "https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html",
                    ),
                    (
                        "Establish standardized naming conventions for observability resources",
                        "Define naming standards for log groups, alarms, dashboards, and metrics so teams can discover and reuse each other's work.",
                        "https://docs.aws.amazon.com/prescriptive-guidance/latest/implementing-logging-monitoring-cloudwatch/cloudwatch-dashboards-visualizations.html",
                    ),
                    (
                        "Set up centralized monitoring with cross-account observability",
                        "Establish a monitoring account with Observability Access Manager for unified visibility across your organization.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Unified-Cross-Account.html",
                    ),
                ],
                2: [  # L2 → L3: unified tools → best practices and training
                    (
                        "Include observability from day one in development",
                        "Embed observability into your development lifecycle — instrument early, not as an afterthought, to accelerate development.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#include-observability-from-day-one",
                    ),
                    (
                        "Create observability runbooks and training materials",
                        "Document standard operating procedures for common troubleshooting scenarios and train teams on observability best practices.",
                        "https://aws-observability.github.io/observability-best-practices/guides/",
                    ),
                    (
                        "Integrate observability with existing ITSM tools",
                        "Connect CloudWatch alarms to your existing ticketing and escalation tools (ServiceNow, PagerDuty) for streamlined workflows.",
                        "https://aws-observability.github.io/observability-best-practices/signals/alarms/#use-your-existing-itsm-and-support-processes",
                    ),
                    (
                        "Deploy observability infrastructure as code",
                        "Manage dashboards, alarms, and monitoring configuration with CloudFormation or CDK for consistency and repeatability.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html",
                    ),
                ],
                3: [  # L3 → L4: best practices → culture of continuous improvement
                    (
                        "Adopt the AWS Observability Maturity Model for continuous assessment",
                        "Use the maturity model framework to regularly assess and improve your observability practices across the organization.",
                        "https://aws-observability.github.io/observability-best-practices/guides/observability-maturity-model/",
                    ),
                    (
                        "Align observability strategy with business outcomes",
                        "Ensure your observability strategy starts from business KPIs and works backwards to infrastructure metrics.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#monitor-what-matters",
                    ),
                    (
                        "Establish regular observability reviews and feedback loops",
                        "Conduct periodic reviews of alarm quality, dashboard effectiveness, and coverage gaps — feed learnings back into standards.",
                        "https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_event_response_dashboards.html",
                    ),
                ],
            },
            13: {  # Q13: How do you use SLOs?
                1: [  # L1 → L2: team experimentation → enterprise adoption for reliability
                    (
                        "Enable Application Signals for automatic SLI collection",
                        "Use Application Signals to automatically collect Service Level Indicators (latency, errors, faults) per service as the foundation for SLOs.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals.html",
                    ),
                    (
                        "Define SLOs on critical services using Application Signals",
                        "Move beyond experimentation — create formal SLOs on your most critical services to establish enterprise-wide reliability targets.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals-SLOs.html",
                    ),
                    (
                        "Identify your KPIs and work backwards to SLIs",
                        "Start from business outcomes to identify which service metrics matter most, then define SLIs that measure them.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#know-your-objectives-and-measure-them",
                    ),
                    (
                        "Create alarms on SLO breach thresholds",
                        "Set up CloudWatch alarms that notify teams when SLOs are at risk of being breached.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals-SLOs.html",
                    ),
                ],
                2: [  # L2 → L3: enterprise adoption → prioritization for users and business
                    (
                        "Track SLOs across all critical user journeys",
                        "Expand SLO coverage beyond individual services to cover end-to-end user journeys and business-critical paths.",
                        "https://aws.amazon.com/cloudwatch/features/application-observability-apm/",
                    ),
                    (
                        "Align SLOs with business priorities and customer expectations",
                        "Ensure SLO targets reflect actual business requirements — not just technical thresholds — so reliability work is prioritized by user impact.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#monitor-what-matters",
                    ),
                    (
                        "Create SLO burn rate alarms for early warning",
                        "Set up alarms that trigger when error budgets are being consumed too quickly, giving teams time to react before SLOs are breached.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals-SLOs.html",
                    ),
                ],
                3: [  # L3 → L4: prioritization → integrated platforms with error budgets
                    (
                        "Implement error budget policies with automated responses",
                        "Define policies for what happens when error budgets are exhausted — freeze deployments, increase testing, or scale resources.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals-SLOs.html",
                    ),
                    (
                        "Integrate SLO health into CI/CD pipelines",
                        "Gate deployments based on error budget status — prevent releases when budgets are low to protect reliability.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals.html",
                    ),
                    (
                        "Build executive SLO dashboards with error budget tracking",
                        "Create dashboards that give leadership visibility into service reliability, error budget burn rates, and SLO compliance trends.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html",
                    ),
                ],
            },
            17: {  # Q17: Are you getting ROI from your observability tools?
                1: [  # L1 → L2: want optimization without knowledge → vendor consolidation
                    (
                        "Consolidate observability tools to reduce vendor sprawl",
                        "Audit your current observability tools and consolidate onto fewer platforms to reduce licensing costs and operational overhead.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#every-workload-is-different-but-common-tools-make-for-a-faster-results",
                    ),
                    (
                        "Analyze CloudWatch Logs usage with the automatic dashboard",
                        "Use the enhanced automatic dashboard to understand log ingestion patterns and identify cost optimization opportunities.",
                        "https://aws.amazon.com/blogs/mt/analyze-logs-usage-with-amazon-cloudwatch-enhanced-automatic-dashboard/",
                    ),
                    (
                        "Use Infrequent Access log class for low-query log groups",
                        "Move infrequently queried log groups to the IA class for up to 50% lower ingestion costs.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch_Logs_Log_Classes.html",
                    ),
                    (
                        "Filter logs close to the source to reduce ingestion costs",
                        "Reduce log volume by filtering unnecessary data before it reaches CloudWatch — less ingestion means lower costs.",
                        "https://aws-observability.github.io/observability-best-practices/signals/logs/#filter-logs-close-to-the-source",
                    ),
                ],
                2: [  # L2 → L3: vendor consolidation → established validation policies
                    (
                        "Establish cost validation policies for observability resources",
                        "Create policies that require teams to justify observability costs — review log retention, alarm counts, and custom metric usage regularly.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html",
                    ),
                    (
                        "Avoid double-ingestion antipatterns",
                        "Eliminate unnecessary log duplication across systems — use cross-account observability instead of copying all data.",
                        "https://aws-observability.github.io/observability-best-practices/signals/logs/#avoid-double-ingestion-antipatterns",
                    ),
                    (
                        "Implement S3 lifecycle policies for log archival cost optimization",
                        "Transition archived logs through S3 storage tiers (Standard → IA → Glacier) to minimize long-term storage costs.",
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html",
                    ),
                    (
                        "Right-size metric collection and alarm configurations",
                        "Review custom metrics and alarms to remove unused ones and consolidate overlapping monitoring to reduce costs.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html",
                    ),
                ],
                3: [  # L3 → L4: validation policies → business value and cost optimization
                    (
                        "Measure observability ROI through MTTR and availability improvements",
                        "Track Mean Time To Resolution and availability improvements as key metrics for the business value of your observability investment.",
                        "https://aws-observability.github.io/observability-best-practices/guides/observability-maturity-model/",
                    ),
                    (
                        "Correlate observability investment with business outcomes",
                        "Demonstrate how observability improvements (faster detection, automated remediation) translate to business metrics (uptime, revenue, customer satisfaction).",
                        "https://aws-observability.github.io/observability-best-practices/guides/#monitor-what-matters",
                    ),
                    (
                        "Use field indexes to reduce Logs Insights query costs",
                        "Create field indexes on frequently queried fields to lower scan volume and query costs while improving query performance.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs-Field-Indexing.html",
                    ),
                ],
            },
            14: {  # Q14: Do you use any AI/ML capability today?
                1: [  # L1 → L2: no AI/ML → natural language query capability
                    (
                        "Enable AWS DevOps Agent for natural language queries",
                        "Use AWS DevOps Agent to ask questions about your environment in natural language — the first step into AI-assisted observability.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                    (
                        "Start using CloudWatch Logs Insights pattern analytics",
                        "Use the Patterns tab in Logs Insights to automatically discover recurring patterns in your logs without writing queries.",
                        "https://aws.amazon.com/blogs/aws/amazon-cloudwatch-logs-now-offers-automated-pattern-analytics-and-anomaly-detection/",
                    ),
                    (
                        "Leverage ML to know what good looks like",
                        "Use ML-based tools to automatically baseline your metrics instead of manually determining healthy thresholds.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#use-automation-and-machine-learning",
                    ),
                ],
                2: [  # L2 → L3: natural language queries → automatic correlation and patterns
                    (
                        "Enable CloudWatch Investigations for automated correlation",
                        "Use Investigations to automatically correlate anomalies across logs, metrics, and traces during incidents.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/investigations.html",
                    ),
                    (
                        "Deploy anomaly detection on logs and metrics",
                        "Enable ML-based anomaly detection on both log groups and key metrics for automatic pattern recognition.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html",
                    ),
                    (
                        "Enable log anomaly detection for automated pattern analysis",
                        "Activate log anomaly detectors to automatically surface unusual log patterns using ML — no manual thresholds needed.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/LogsAnomalyDetection.html",
                    ),
                    (
                        "Enable X-Ray Insights for trace anomaly detection",
                        "Turn on X-Ray Insights to automatically detect latency and error rate anomalies in your trace data.",
                        "https://docs.aws.amazon.com/xray/latest/devguide/xray-console-insights.html",
                    ),
                ],
                3: [  # L3 → L4: automatic correlation → comprehensive AI/ML with real-time
                    (
                        "Use AWS DevOps Agent for comprehensive real-time AI troubleshooting",
                        "Leverage AWS DevOps Agent for real-time AI analysis across all signals — logs, metrics, traces — with automated root cause identification.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/devops-agent.html",
                    ),
                    (
                        "Automate remediation with AI-triggered workflows",
                        "Connect AI-detected anomalies to Systems Manager automation runbooks and Incident Manager for self-healing infrastructure.",
                        "https://docs.aws.amazon.com/incident-manager/latest/userguide/what-is-incident-manager.html",
                    ),
                    (
                        "Achieve comprehensive AI coverage across all signal types",
                        "Ensure anomaly detection covers logs, metrics, and traces — combined with AI-assisted analysis for fully proactive observability.",
                        "https://aws-observability.github.io/observability-best-practices/guides/observability-maturity-model/",
                    ),
                ],
            },
            15: {  # Q15: Do you have real end-user monitoring?
                1: [  # L1 → L2: test users for validation → synthetic scripts on schedule
                    (
                        "Set up CloudWatch Synthetics canaries on a schedule",
                        "Create synthetic canaries that run on a regular schedule to proactively test your application endpoints before users report issues.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries.html",
                    ),
                    (
                        "Create alarms on canary success rates and latency",
                        "Set up CloudWatch alarms on canary metrics to detect endpoint degradation before real users are impacted.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries.html",
                    ),
                    (
                        "Don't forget about the end-user experience",
                        "Measure and understand how end users actually experience your application — it matters more than server metrics alone.",
                        "https://aws-observability.github.io/observability-best-practices/guides/#dont-forget-about-the-end-user-experience",
                    ),
                ],
                2: [  # L2 → L3: synthetic scripts → scripted interaction tests with correlation
                    (
                        "Create multi-step canaries for complex user journey testing",
                        "Build canaries that simulate complex user interactions (login, search, checkout) to validate critical business flows end-to-end.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries.html",
                    ),
                    (
                        "Enable X-Ray tracing on synthetic canaries",
                        "Turn on X-Ray tracing for canaries to correlate synthetic test failures with backend service traces for faster root cause analysis.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries.html",
                    ),
                    (
                        "Implement user experience telemetry with RUM and Synthetics",
                        "Deploy both synthetic monitoring and real user monitoring for a holistic view of the customer experience.",
                        "https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_observability_customer_telemetry.html",
                    ),
                ],
                3: [  # L3 → L4: scripted tests with correlation → real user monitoring with proactive anomalies
                    (
                        "Deploy CloudWatch RUM for real user monitoring",
                        "Install the CloudWatch RUM JavaScript client to collect real user performance data, errors, and session details from actual users.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM.html",
                    ),
                    (
                        "Enable RUM with X-Ray for end-to-end user journey tracing",
                        "Connect RUM to X-Ray to trace real user requests from the browser through your entire backend service chain.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM.html",
                    ),
                    (
                        "Set up anomaly detection on RUM and Synthetics metrics",
                        "Create anomaly detection alarms on user experience metrics to proactively detect degradation before users complain.",
                        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html",
                    ),
                ],
            },
        }
        q_recs = recs.get(question_id, {})
        return q_recs.get(current_level, [])
