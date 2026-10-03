// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@cloudscape-design/global-styles/index.css';
import { applyMode, Mode } from '@cloudscape-design/global-styles';
import { useCollection } from '@cloudscape-design/collection-hooks';
import {
  Alert,
  AppLayout,
  BarChart,
  Box,
  ColumnLayout,
  Container,
  CopyToClipboard,
  ExpandableSection,
  Header,
  Link,
  Pagination,
  SpaceBetween,
  SplitPanel,
  StatusIndicator,
  Table,
  Tabs,
  TextFilter,
  TopNavigation,
  type TableProps
} from '@cloudscape-design/components';
import {
  countText,
  isExternalHref,
  matchesCategory,
  parseReport,
  safeHref,
  scoreText,
  timeText,
  type Account,
  type Category,
  type DiscoveryCheck,
  type OrganizationReport,
  type Question,
  type Report,
  type SingleAccountReport
} from './data';
import { AssessmentMethodology } from './methodology';
import './report.css';

const CHART_STRINGS = {
  filterLabel: 'Filter data',
  filterPlaceholder: 'Select series',
  filterSelectedAriaLabel: 'selected',
  legendAriaLabel: 'Legend',
  detailPopoverDismissAriaLabel: 'Dismiss details',
  chartAriaRoleDescription: 'Bar chart',
  xAxisAriaRoleDescription: 'Categories',
  yAxisAriaRoleDescription: 'Values'
};
const MODE_STORAGE_KEY = 'observability-assessment-report-mode';

function preferredMode(): Mode {
  try {
    const saved = window.localStorage.getItem(MODE_STORAGE_KEY);
    if (saved === Mode.Light || saved === Mode.Dark) return saved;
  } catch {
    // Local file reports can deny storage access. The toggle still works for this view.
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? Mode.Dark : Mode.Light;
}

function ModeIcon({ targetMode }: { targetMode: Mode }) {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {targetMode === Mode.Light ? (
        <>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2 M12 20v2 M4.93 4.93l1.42 1.42 M17.65 17.65l1.42 1.42 M2 12h2 M20 12h2 M4.93 19.07l1.42-1.42 M17.65 6.35l1.42-1.42" />
        </>
      ) : (
        <path d="M20.5 15.5A8.5 8.5 0 0 1 8.5 3.5 8.5 8.5 0 1 0 20.5 15.5Z" />
      )}
    </svg>
  );
}

function Stat({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box variant="h2" className="report-score">{value}</Box>
      {detail && <Box color="text-body-secondary">{detail}</Box>}
    </div>
  );
}

function OptionalLink({ href, children }: { href: string | null | undefined; children: React.ReactNode }) {
  const url = safeHref(href);
  return url ? (
    <Link href={url} external={isExternalHref(url)} target={isExternalHref(url) ? '_blank' : undefined}>
      {children}
    </Link>
  ) : <>{children}</>;
}

function levelCount(questions: Question[], level: number): number {
  return questions.filter(question => question.assessed && question.level === level).length;
}

function questionPartial(question: Question): boolean {
  return (question.unavailableCheckIds?.length ?? 0) > 0 ||
    (question.incompleteCheckIds?.length ?? 0) > 0;
}

function categoryComparison(categories: Category[]): string {
  const scored = categories.filter(category =>
    category.assessedCount > 0 && typeof category.score === 'number' && Number.isFinite(category.score)
  );
  if (scored.length === 0) return 'Category comparison: N/A; no category has assessed questions.';
  if (scored.length === 1) return `Assessed category: ${scored[0].label} (${scoreText(scored[0].score)}).`;
  const scores = scored.map(category => category.score as number);
  const maximum = Math.max(...scores);
  const minimum = Math.min(...scores);
  if (maximum === minimum) {
    return `All assessed categories are tied at ${scoreText(maximum)}.`;
  }
  const strongest = scored.filter(category => category.score === maximum).map(category => category.label).join(', ');
  const weakest = scored.filter(category => category.score === minimum).map(category => category.label).join(', ');
  return `Strongest assessed ${strongest.includes(',') ? 'categories' : 'category'}: ${strongest} (${scoreText(maximum)}). Lowest assessed ${weakest.includes(',') ? 'categories' : 'category'}: ${weakest} (${scoreText(minimum)}).`;
}

interface FocusItem {
  title: string;
  questions: Question[];
}

function suggestedFocus(questions: Question[]): FocusItem[] {
  const assessed = questions.filter(question =>
    question.assessed && typeof question.level === 'number' && Number.isFinite(question.level)
  );
  const groups = [
    { title: 'Review alarm and dashboard coverage', ids: [10, 11] },
    { title: 'Review metric coverage', ids: [5] },
    { title: 'Review log retention', ids: [4] }
  ];
  const selected = new Set<number>();
  const items: FocusItem[] = [];
  for (const group of groups) {
    const matches = assessed.filter(question =>
      group.ids.includes(question.id) && (question.level as number) <= 2
    );
    if (matches.length > 0) {
      items.push({ title: group.title, questions: matches });
      matches.forEach(question => selected.add(question.id));
    }
  }
  for (const question of [...assessed].sort((a, b) =>
    (a.level as number) - (b.level as number) || a.id - b.id
  )) {
    if (items.length >= 3) break;
    if (!selected.has(question.id)) {
      items.push({ title: `Review findings for Q${question.id}`, questions: [question] });
      selected.add(question.id);
    }
  }
  return items;
}

function questionStatus(question: Question) {
  if (!question.assessed) return <StatusIndicator type="stopped">Not assessed</StatusIndicator>;
  if (questionPartial(question)) return <StatusIndicator type="warning">Partial evidence</StatusIndicator>;
  return <StatusIndicator type="success">Assessed</StatusIndicator>;
}

function QuestionDetail({
  question,
  expanded,
  onExpandedChange
}: {
  question: Question;
  expanded: boolean;
  onExpandedChange: (expanded: boolean) => void;
}) {
  const evidenceIds = Array.isArray(question.evidenceCheckIds) ? question.evidenceCheckIds : [];
  const unavailableIds = Array.isArray(question.unavailableCheckIds) ? question.unavailableCheckIds : [];
  const incompleteIds = Array.isArray(question.incompleteCheckIds) ? question.incompleteCheckIds : [];
  const levels = Array.isArray(question.maturityDescriptions) ? question.maturityDescriptions : [];
  const recommendations = Array.isArray(question.recommendations) ? question.recommendations : [];

  return (
    <div id={`question-${question.id}`} className="report-question-anchor" tabIndex={-1}>
      <ExpandableSection
        variant="container"
        headingTagOverride="h3"
        headerText={<Box variant="span" fontWeight="normal">{`Q${question.id}. ${question.question}`}</Box>}
        headerCounter={!question.assessed
          ? 'Not assessed'
          : `${Number.isFinite(question.level) ? `Level ${question.level}` : 'N/A'}${questionPartial(question) ? ' · Partial evidence' : ''}`}
        expanded={expanded}
        onChange={({ detail }) => onExpandedChange(detail.expanded)}
      >
        <SpaceBetween size="m">
          {questionStatus(question)}
          {!question.assessed && (
            <Alert type="warning" header="Question not assessed">
              Required discovery evidence was unavailable. No maturity level is assigned.
            </Alert>
          )}
          {unavailableIds.length > 0 && (
            <Alert type="warning" header="Incomplete data">
              Discovery checks {unavailableIds.map(id => `#${id}`).join(', ')} were unavailable.
              The reported level may understate actual maturity.
            </Alert>
          )}
          {incompleteIds.length > 0 && (
            <Alert type="warning" header="Partial data">
              Discovery checks {incompleteIds.map(id => `#${id}`).join(', ')} could not read some resources.
            </Alert>
          )}
          <ColumnLayout columns={2} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Selected level</Box>
              <Box>{question.assessed && Number.isFinite(question.level)
                ? `Level ${question.level}${question.levelLabel ? ` — ${question.levelLabel}` : ''}`
                : 'N/A'}</Box>
            </div>
            <div>
              <Box variant="awsui-key-label">Discovery checks used</Box>
              <Box>{evidenceIds.length > 0 ? evidenceIds.map(id => `#${id}`).join(', ') : 'None listed'}</Box>
            </div>
          </ColumnLayout>
          <div>
            <Box variant="awsui-key-label">Evidence and explanation</Box>
            <div className="report-evidence">{question.explanation || 'No explanation provided.'}</div>
          </div>
          <div>
            <Box variant="h4">Maturity levels</Box>
            <SpaceBetween size="xs">
              {levels.map(item => (
                <div key={item.level}>
                  {question.assessed && item.level === question.level ? (
                    <StatusIndicator type="success">Level {item.level}: {item.description}</StatusIndicator>
                  ) : (
                    <Box>Level {item.level}: {item.description}</Box>
                  )}
                </div>
              ))}
            </SpaceBetween>
          </div>
          {question.assessed && recommendations.length > 0 && (
            <ExpandableSection headerText="Recommendations" headingTagOverride="h4">
              <SpaceBetween size="s">
                {recommendations.map((item, index) => (
                  <div key={`${item.title}-${index}`}>
                    <OptionalLink href={item.url}>{item.title}</OptionalLink>
                    <Box color="text-body-secondary">{item.description}</Box>
                  </div>
                ))}
              </SpaceBetween>
            </ExpandableSection>
          )}
        </SpaceBetween>
      </ExpandableSection>
    </div>
  );
}

function discoveryStatus(check: DiscoveryCheck) {
  return check.status === 'success'
    ? <StatusIndicator type="success">Evaluated</StatusIndicator>
    : check.status === 'error'
      ? <StatusIndicator type="error">Unavailable</StatusIndicator>
      : <StatusIndicator type="warning">{check.status || 'Unknown'}</StatusIndicator>;
}

function evidenceMetrics(summary: string): { label: string; value: string }[] | null {
  const parts = summary.split(/\s+\|\s+/);
  if (parts.length < 2 || parts.length > 4) return null;
  const metrics: { label: string; value: string }[] = [];
  for (const part of parts) {
    const match = part.match(/^([^:\n]{1,32}):\s*(.+)$/);
    if (!match) return null;
    metrics.push({ label: match[1].trim(), value: match[2].trim() });
  }
  return metrics;
}

type EvidenceBlock = { kind: 'heading' | 'list' | 'text'; lines: string[] };

function evidenceBlocks(details: string): EvidenceBlock[] {
  const blocks: EvidenceBlock[] = [];
  let newBlock = false;
  for (const rawLine of details.split('\n')) {
    const line = rawLine.trim();
    if (!line) {
      newBlock = true;
      continue;
    }
    const bullet = line.match(/^[•*-]\s+(.+)$/);
    const kind: EvidenceBlock['kind'] = bullet
      ? 'list'
      : line.endsWith(':') && line.length <= 100
        ? 'heading'
        : 'text';
    const value = bullet ? bullet[1] : line;
    const previous = blocks[blocks.length - 1];
    if (!newBlock && previous?.kind === kind && kind !== 'heading') {
      previous.lines.push(value);
    } else {
      blocks.push({ kind, lines: [value] });
    }
    newBlock = false;
  }
  return blocks;
}

function EvidenceContent({ check }: { check: DiscoveryCheck }) {
  const summary = check.evidenceSummary || (check.evidenceDetails ? '' : check.evidenceText) || '';
  const details = check.evidenceDetails || '';
  const metrics = evidenceMetrics(summary);
  const blocks = evidenceBlocks(details);
  return (
    <Container header={<Header variant="h3">Evidence</Header>}>
      <SpaceBetween size="m">
        {metrics ? (
          <ColumnLayout columns={metrics.length} variant="text-grid">
            {metrics.map(metric => (
              <div key={metric.label}>
                <Box variant="awsui-key-label">{metric.label}</Box>
                <Box>{metric.value}</Box>
              </div>
            ))}
          </ColumnLayout>
        ) : summary ? (
          <div className="report-evidence">{summary}</div>
        ) : blocks.length === 0 ? <Box>No evidence text provided.</Box> : null}
        {blocks.length > 0 && (
          <ExpandableSection headerText="Supporting details">
            <div className="report-evidence-details">
              <SpaceBetween size="m">
                {blocks.map((block, index) => block.kind === 'heading' ? (
                  <Box key={index} variant="h4">{block.lines[0]}</Box>
                ) : block.kind === 'list' ? (
                  <ul key={index} className="report-evidence-list">
                    {block.lines.map((line, lineIndex) => <li key={lineIndex}>{line}</li>)}
                  </ul>
                ) : (
                  <div key={index} className="report-evidence-lines">
                    {block.lines.map((line, lineIndex) => <div key={lineIndex}>{line}</div>)}
                  </div>
                ))}
              </SpaceBetween>
            </div>
          </ExpandableSection>
        )}
      </SpaceBetween>
    </Container>
  );
}

function DiscoveryDetails({ check, region }: { check: DiscoveryCheck; region: string }) {
  return (
    <SpaceBetween size="l">
      <Box variant="h3">{check.name}</Box>
      <ColumnLayout columns={2} variant="text-grid">
        <div>
          <Box variant="awsui-key-label">Check ID</Box>
          <Box>#{check.id}</Box>
        </div>
        <div>
          <Box variant="awsui-key-label">Status</Box>
          {discoveryStatus(check)}
        </div>
        <div>
          <Box variant="awsui-key-label">Category</Box>
          <Box>{check.category}</Box>
        </div>
        <div>
          <Box variant="awsui-key-label">Assessment region</Box>
          <Box>{region || 'N/A'}</Box>
        </div>
      </ColumnLayout>
      <EvidenceContent check={check} />
      <Container
        header={
          <Header
            variant="h3"
            actions={check.command ? (
              <CopyToClipboard
                variant="icon"
                textToCopy={check.command}
                copyButtonAriaLabel="Copy discovery command"
                copySuccessText="Command copied"
                copyErrorText="Could not copy command"
              />
            ) : undefined}
          >
            Command
          </Header>
        }
      >
        <code className="report-command">{check.command || 'N/A'}</code>
      </Container>
    </SpaceBetween>
  );
}

function DiscoveryTable({
  checks,
  selectedCheck,
  onSelect
}: {
  checks: DiscoveryCheck[];
  selectedCheck: DiscoveryCheck | null;
  onSelect: (check: DiscoveryCheck | null) => void;
}) {
  const columns: TableProps.ColumnDefinition<DiscoveryCheck>[] = [
    { id: 'id', header: 'ID', cell: item => `#${item.id}`, sortingField: 'id', width: 110, minWidth: 110 },
    { id: 'name', header: 'Discovery check', cell: item => item.name, sortingField: 'name', minWidth: 200 },
    { id: 'category', header: 'Category', cell: item => item.category, sortingField: 'category', minWidth: 140 },
    {
      id: 'status',
      header: 'Status',
      cell: item => discoveryStatus(item),
      sortingField: 'status',
      minWidth: 135
    }
  ];
  const { items, collectionProps, filterProps, paginationProps, filteredItemsCount } = useCollection(checks, {
    filtering: {
      filteringFunction: (item, text) => (
        [item.id, item.name, item.category, item.status, item.command, item.evidenceText]
          .some(value => String(value ?? '').toLowerCase().includes(text.toLowerCase()))
      ),
      empty: <Box textAlign="center">No discovery checks are available.</Box>,
      noMatch: <Box textAlign="center">No checks match the filter.</Box>
    },
    sorting: { defaultState: { sortingColumn: { sortingField: 'id' } } },
    pagination: { pageSize: 10 }
  });
  return (
    <Table
      {...collectionProps}
      items={items}
      trackBy="id"
      columnDefinitions={columns}
      selectionType="single"
      selectedItems={selectedCheck ? [selectedCheck] : []}
      onSelectionChange={({ detail }) => onSelect(detail.selectedItems[0] ?? null)}
      ariaLabels={{
        selectionGroupLabel: 'Select a discovery check',
        itemSelectionLabel: (_, item) => `View details for discovery check #${item.id}: ${item.name}`
      }}
      wrapLines
      stickyHeader
      header={<Header variant="h2" counter={`(${checks.length})`} description="Select a check to view its evidence and command.">Discovery checks</Header>}
      filter={
        <TextFilter
          {...filterProps}
          filteringAriaLabel="Filter discovery checks"
          filteringPlaceholder="Search checks, status, commands, or evidence"
          countText={`${filteredItemsCount ?? checks.length} matches`}
        />
      }
      pagination={<Pagination {...paginationProps} ariaLabels={{
        nextPageLabel: 'Next page',
        previousPageLabel: 'Previous page',
        pageLabel: pageNumber => `Page ${pageNumber}`
      }} />}
    />
  );
}

function SingleAccountView({ report }: { report: SingleAccountReport }) {
  const { meta, summary, categories, questions, discovery } = report;
  const [activeTabId, setActiveTabId] = useState(categories[0]?.id ?? '');
  const [expandedQuestions, setExpandedQuestions] = useState<Record<number, boolean>>({});
  const [selectedCheckId, setSelectedCheckId] = useState<number | null>(null);
  const [detailPanelPosition, setDetailPanelPosition] = useState<'side' | 'bottom'>('side');
  const [detailPanelSizes, setDetailPanelSizes] = useState({ side: 480, bottom: 360 });
  const selectedCheck = discovery.find(check => check.id === selectedCheckId) ?? null;
  const firstLevelCount = levelCount(questions, 1);
  const focusItems = useMemo(() => suggestedFocus(questions), [questions]);

  function jumpToQuestion(question: Question) {
    const category = categories.find(item => matchesCategory(question.category, item));
    if (category) setActiveTabId(category.id);
    setExpandedQuestions(current => ({ ...current, [question.id]: true }));
    window.setTimeout(() => {
      const target = document.getElementById(`question-${question.id}`);
      target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      target?.focus({ preventScroll: true });
    }, 0);
  }

  const categoryNames = categories.map(category => category.label);
  const categoryScores = categories
    .filter(category => category.assessedCount > 0 && typeof category.score === 'number' && Number.isFinite(category.score))
    .map(category => ({ x: category.label, y: category.score as number }));
  const distributionSeries = [
    ...[1, 2, 3, 4].map(level => ({
      title: `Level ${level}`,
      type: 'bar' as const,
      data: categories.map(category => ({
        x: category.label,
        y: questions.filter(question => matchesCategory(question.category, category) && question.assessed && question.level === level).length
      }))
    })),
    {
      title: 'Not assessed',
      type: 'bar' as const,
      data: categories.map(category => ({
        x: category.label,
        y: questions.filter(question => matchesCategory(question.category, category) && !question.assessed).length
      }))
    }
  ];
  const maxCategoryQuestions = Math.max(1, ...categories.map(category =>
    questions.filter(question => matchesCategory(question.category, category)).length
  ));
  const hasUnavailableEvidence = summary.discoveryUnavailable > 0 ||
    summary.discoveryEvaluated < summary.discoveryTotal ||
    summary.questionsAssessed < summary.questionsTotal;
  const hasEvidenceGap = hasUnavailableEvidence || summary.partialQuestions > 0;

  return (
    <AppLayout
      headerSelector="#report-top-navigation"
      navigationHide
      toolsHide
      disableContentPaddings
      maxContentWidth={Number.MAX_VALUE}
      splitPanel={selectedCheck ? (
        <SplitPanel
          header={`Discovery check #${selectedCheck.id}`}
          ariaLabel={`Details for discovery check #${selectedCheck.id}`}
          closeBehavior="hide"
          i18nStrings={{
            closeButtonAriaLabel: 'Close discovery check details',
            openButtonAriaLabel: 'Open discovery check details',
            preferencesTitle: 'Panel preferences',
            preferencesPositionLabel: 'Panel position',
            preferencesPositionDescription: 'Choose where discovery check details appear.',
            preferencesPositionSide: 'Side',
            preferencesPositionBottom: 'Bottom',
            preferencesConfirm: 'Confirm',
            preferencesCancel: 'Cancel',
            preferencesCloseAriaLabel: 'Close panel preferences',
            resizeHandleAriaLabel: 'Resize discovery check details'
          }}
        >
          <DiscoveryDetails check={selectedCheck} region={meta.region} />
        </SplitPanel>
      ) : undefined}
      splitPanelOpen={selectedCheck !== null}
      splitPanelSize={detailPanelSizes[detailPanelPosition]}
      splitPanelPreferences={{ position: detailPanelPosition }}
      onSplitPanelPreferencesChange={({ detail }) => setDetailPanelPosition(detail.position)}
      onSplitPanelResize={({ detail }) => setDetailPanelSizes(current => ({
        ...current,
        [detailPanelPosition]: detail.size
      }))}
      onSplitPanelToggle={({ detail }) => {
        if (!detail.open) setSelectedCheckId(null);
      }}
      content={(
        <main id="report-start" className="report-shell report-wrap">
      <SpaceBetween size="l">
        <div>
          {meta.backLink && <Box margin={{ bottom: 's' }}><OptionalLink href={meta.backLink}>← Back to organization summary</OptionalLink></Box>}
          <Header variant="h1" description={`Account ${meta.accountId || 'N/A'} · ${meta.region || 'N/A'} · Generated ${timeText(meta.generatedAt)}`}>
            Account assessment results
          </Header>
        </div>
        <Container header={<Header variant="h2">Executive summary</Header>}>
          <SpaceBetween size="l">
            <div className="report-summary-grid">
              <div className="report-maturity-card">
                <span className="report-summary-eyebrow">Overall maturity</span>
                <strong className="report-maturity-score">{scoreText(summary.overallScore, summary.questionsAssessed > 0)}</strong>
                <div className="report-maturity-meta">
                  <span className="report-maturity-badge">
                    {summary.questionsAssessed > 0 ? summary.maturityLevel || 'Level unavailable' : 'Not assessed'}
                  </span>
                  <span>
                    {summary.questionsAssessed > 0
                      ? `${summary.questionsAssessed} of ${summary.questionsTotal} questions assessed`
                      : 'No questions had evaluable evidence'}
                  </span>
                </div>
              </div>
              <div className="report-takeaway-card">
                <span className="report-summary-eyebrow">Key takeaway</span>
                <h3 className="report-takeaway-title">
                  {summary.questionsAssessed > 0
                    ? `${firstLevelCount} of ${summary.questionsAssessed} assessed questions are at Level 1`
                    : 'No maturity result is available'}
                </h3>
                <p className="report-takeaway-detail">{categoryComparison(categories)}</p>
              </div>
            </div>
            {hasEvidenceGap && (
              <Alert
                type={hasUnavailableEvidence ? 'warning' : 'info'}
                header={hasUnavailableEvidence ? 'Review evidence coverage' : 'Partial evidence in assessed results'}
              >
                {hasUnavailableEvidence
                  ? `${countText(summary.discoveryEvaluated)} of ${countText(summary.discoveryTotal)} discovery checks evaluated; ${countText(summary.questionsAssessed)} of ${countText(summary.questionsTotal)} questions assessed.${summary.partialQuestions > 0 ? ` ${countText(summary.partialQuestions)} assessed ${summary.partialQuestions === 1 ? 'question has' : 'questions have'} partial evidence.` : ''} Review the unavailable evidence before relying on affected scores.`
                  : `${countText(summary.partialQuestions)} of ${countText(summary.questionsAssessed)} assessed questions have partial evidence. Review their discovery check details before relying on those scores.`}
              </Alert>
            )}
            {focusItems.length > 0 && (
              <SpaceBetween size="m">
                <Header variant="h3" description="Selected from lower-scoring assessed questions">Priority areas</Header>
                <div className="report-priority-grid">
                  {focusItems.map((item, index) => (
                    <article key={item.title} className="report-priority-card">
                      <span className="report-priority-number" aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
                      <h4>{item.title}</h4>
                      <div className="report-priority-questions">
                        {item.questions.map(question => (
                          <div key={question.id} className="report-priority-question">
                            <Link href={`#question-${question.id}`} onFollow={event => {
                              event.preventDefault();
                              jumpToQuestion(question);
                            }}>
                              Q{question.id}
                            </Link>
                            <span className="report-level-tag">Level {question.level}</span>
                            {questionPartial(question) && <span className="report-partial-tag">Partial evidence</span>}
                          </div>
                        ))}
                      </div>
                    </article>
                  ))}
                </div>
              </SpaceBetween>
            )}
            <p className="report-summary-note">
              Scores reflect available discovery evidence for this account and region at generation time.
              They do not establish that every resource or practice was evaluated.
            </p>
          </SpaceBetween>
        </Container>
        <Container header={<Header variant="h2">Assessment at a glance</Header>}>
          <div className="report-glance-grid">
            <div className="report-glance-item">
              <Stat label="Discovery evaluated" value={`${countText(summary.discoveryEvaluated)} / ${countText(summary.discoveryTotal)}`} detail={`${countText(summary.discoveryUnavailable)} unavailable`} />
            </div>
            <div className="report-glance-item">
              <Stat label="Questions assessed" value={`${countText(summary.questionsAssessed)} / ${countText(summary.questionsTotal)}`} detail={`${countText(summary.questionsTotal - summary.questionsAssessed)} not assessed`} />
            </div>
            <div className="report-glance-item">
              <Stat label="Partial questions" value={countText(summary.partialQuestions)} detail="Among assessed questions" />
            </div>
            <div className="report-glance-item">
              <Stat label="Questions at Level 1" value={summary.questionsAssessed > 0 ? String(firstLevelCount) : 'N/A'} detail={summary.questionsAssessed > 0 ? 'From assessed questions' : 'No assessed questions'} />
            </div>
          </div>
        </Container>
        <ColumnLayout columns={2}>
          <Container header={<Header variant="h2">Category scores</Header>} className="report-category-chart">
            <BarChart
              series={[{ title: 'Maturity score', type: 'bar', data: categoryScores }]}
              xDomain={categoryNames}
              yDomain={[0, 4]}
              xScaleType="categorical"
              xTitle="Category"
              yTitle="Maturity level"
              yTickFormatter={value => Number.isInteger(value) ? String(value) : value.toFixed(1)}
              height={320}
              hideFilter
              ariaLabel="Category scores"
              ariaDescription="Average maturity score from assessed questions in each category. Maturity levels are 1 through 4; the chart axis starts at 0 as a visual baseline."
              i18nStrings={CHART_STRINGS}
              empty={<Box>No categories have assessed questions.</Box>}
            />
          </Container>
          <Container header={<Header variant="h2">Question level distribution</Header>} className="report-distribution-chart">
            <BarChart
              series={distributionSeries}
              xDomain={categoryNames}
              yDomain={[0, maxCategoryQuestions]}
              xScaleType="categorical"
              xTitle="Category"
              yTitle="Questions"
              yTickFormatter={value => Number.isInteger(value) ? String(value) : ''}
              stackedBars
              height={320}
              ariaLabel="Question level distribution"
              ariaDescription="Count of questions at maturity levels 1 through 4, plus not assessed questions, grouped by category. The count axis starts at 0."
              i18nStrings={CHART_STRINGS}
              empty={<Box>No questions are available.</Box>}
            />
          </Container>
        </ColumnLayout>
        <Container header={<Header variant="h2">Assessment questions</Header>}>
          {categories.length > 0 ? (
            <Tabs
              ariaLabel="Assessment categories"
              activeTabId={activeTabId}
              onChange={({ detail }) => setActiveTabId(detail.activeTabId)}
              tabs={categories.map((category: Category) => ({
                id: category.id,
                label: category.label,
                content: (
                  <SpaceBetween size="m">
                    <Box color="text-body-secondary">
                      {category.assessedCount} of {category.totalCount} assessed · Score {scoreText(category.score, category.assessedCount > 0)}
                    </Box>
                    {questions.filter(question => matchesCategory(question.category, category)).map(question => (
                      <QuestionDetail
                        key={question.id}
                        question={question}
                        expanded={Boolean(expandedQuestions[question.id])}
                        onExpandedChange={expanded => setExpandedQuestions(current => ({ ...current, [question.id]: expanded }))}
                      />
                    ))}
                  </SpaceBetween>
                )
              }))}
            />
          ) : <Box>No categories are available.</Box>}
        </Container>
        <DiscoveryTable
          checks={discovery}
          selectedCheck={selectedCheck}
          onSelect={check => setSelectedCheckId(check?.id ?? null)}
        />
        <AssessmentMethodology />
      </SpaceBetween>
        </main>
      )}
    />
  );
}

function accountStatus(account: Account) {
  const normalized = account.status?.toLowerCase() || '';
  if (['error', 'failed', 'failure'].includes(normalized)) {
    return <StatusIndicator type="error">Failed</StatusIndicator>;
  }
  if (['partial', 'incomplete'].includes(normalized) ||
    (account.unavailableChecks ?? 0) > 0 ||
    (account.notAssessedQuestions ?? 0) > 0 ||
    (account.partialQuestions ?? 0) > 0) {
    return <StatusIndicator type="warning">Partial evidence</StatusIndicator>;
  }
  if (['success', 'complete', 'completed', 'assessed'].includes(normalized)) {
    return <StatusIndicator type="success">Assessed</StatusIndicator>;
  }
  return <StatusIndicator type="warning">{account.status || 'Unknown'}</StatusIndicator>;
}

function OrganizationAccountsTable({ accounts }: { accounts: Account[] }) {
  const columns: TableProps.ColumnDefinition<Account>[] = [
    {
      id: 'account',
      header: 'Account',
      cell: item => (
        <div>
          <OptionalLink href={item.link}>{item.name || item.id}</OptionalLink>
          {item.name && <Box color="text-body-secondary">{item.id}</Box>}
        </div>
      ),
      sortingComparator: (a, b) => (a.name || a.id).localeCompare(b.name || b.id),
      minWidth: 180
    },
    {
      id: 'status',
      header: 'Status',
      cell: item => <div>{accountStatus(item)}{item.error && <Box color="text-body-secondary">{item.error}</Box>}</div>,
      sortingField: 'status',
      minWidth: 150
    },
    {
      id: 'score',
      header: 'Score',
      cell: item => scoreText(item.score, !['error', 'failed', 'failure'].includes(item.status?.toLowerCase() || '')),
      sortingComparator: (a, b) => (a.score ?? -1) - (b.score ?? -1),
      minWidth: 100
    },
    { id: 'maturity', header: 'Maturity', cell: item => item.maturity || 'N/A', sortingField: 'maturity', minWidth: 140 },
    { id: 'unavailable', header: 'Unavailable checks', cell: item => countText(item.unavailableChecks), sortingField: 'unavailableChecks', minWidth: 130 },
    { id: 'notAssessed', header: 'Unassessed questions', cell: item => countText(item.notAssessedQuestions), sortingField: 'notAssessedQuestions', minWidth: 140 },
    { id: 'partial', header: 'Partial questions', cell: item => countText(item.partialQuestions), sortingField: 'partialQuestions', minWidth: 120 }
  ];
  const { items, collectionProps, filterProps, paginationProps, filteredItemsCount } = useCollection(accounts, {
    filtering: {
      filteringFunction: (item, text) => (
        [item.id, item.name, item.status, item.maturity, item.error]
          .some(value => String(value ?? '').toLowerCase().includes(text.toLowerCase()))
      ),
      empty: <Box textAlign="center">No accounts are available.</Box>,
      noMatch: <Box textAlign="center">No accounts match the filter.</Box>
    },
    sorting: { defaultState: { sortingColumn: { sortingField: 'id' } } },
    pagination: { pageSize: 10 }
  });
  return (
    <Table
      {...collectionProps}
      items={items}
      trackBy="id"
      columnDefinitions={columns}
      wrapLines
      stickyHeader
      header={<Header variant="h2" counter={`(${accounts.length})`}>Accounts</Header>}
      filter={<TextFilter
        {...filterProps}
        filteringAriaLabel="Filter accounts"
        filteringPlaceholder="Search account ID, name, status, or error"
        countText={`${filteredItemsCount ?? accounts.length} matches`}
      />}
      pagination={<Pagination {...paginationProps} ariaLabels={{
        nextPageLabel: 'Next page',
        previousPageLabel: 'Previous page',
        pageLabel: pageNumber => `Page ${pageNumber}`
      }} />}
    />
  );
}

function OrganizationView({ report }: { report: OrganizationReport }) {
  const { meta, summary, categories, accounts } = report;
  const hasScores = summary.scoredAccounts > 0;
  const partialAccounts = accounts.filter(account =>
    !['error', 'failed', 'failure'].includes(account.status?.toLowerCase() || '') &&
    (['partial', 'incomplete'].includes(account.status?.toLowerCase() || '') ||
      (account.unavailableChecks ?? 0) > 0 ||
      (account.notAssessedQuestions ?? 0) > 0 ||
      (account.partialQuestions ?? 0) > 0)
  ).length;
  const categoryScores = categories
    .filter(category => hasScores && typeof category.score === 'number' && Number.isFinite(category.score))
    .map(category => ({ x: category.label, y: category.score as number }));

  return (
    <main id="report-start" className="report-shell report-wrap">
      <SpaceBetween size="l">
        <Header variant="h1" description={`Organization ${meta.organizationId || 'N/A'} · Generated ${timeText(meta.generatedAt)}`}>
          Organization assessment results
        </Header>
        <Container header={<Header variant="h2">Organization overview</Header>}>
          <SpaceBetween size="l">
            <div className="report-summary-grid">
              <div className="report-maturity-card">
                <span className="report-summary-eyebrow">Average maturity</span>
                <strong className="report-maturity-score">{scoreText(summary.averageScore, hasScores)}</strong>
                <div className="report-maturity-meta">
                  <span className="report-maturity-badge">{hasScores ? summary.maturityLevel || 'Level unavailable' : 'Not assessed'}</span>
                  <span>
                    {hasScores
                      ? `Across ${summary.scoredAccounts} scored ${summary.scoredAccounts === 1 ? 'account' : 'accounts'}`
                      : 'No accounts had assessed questions'}
                  </span>
                </div>
              </div>
              <div className="report-takeaway-card">
                <span className="report-summary-eyebrow">Score range</span>
                {hasScores ? (
                  <>
                    <div className="report-range-values">
                      <div>
                        <span className="report-range-label">Lowest</span>
                        <strong className="report-range-score">{scoreText(summary.minScore)}</strong>
                      </div>
                      <div>
                        <span className="report-range-label">Highest</span>
                        <strong className="report-range-score">{scoreText(summary.maxScore)}</strong>
                      </div>
                    </div>
                    <p className="report-takeaway-detail">Best maturity: {summary.bestMaturityLevel || 'N/A'}</p>
                  </>
                ) : (
                  <h3 className="report-takeaway-title">No score range is available</h3>
                )}
              </div>
            </div>
            {summary.failedAccounts > 0 && (
              <Alert type="warning" header="Some accounts could not be assessed">
                {summary.failedAccounts} of {summary.totalAccounts} accounts failed. Review their status and errors in the account table.
              </Alert>
            )}
            {partialAccounts > 0 && (
              <Alert type="warning" header="Some account results use partial evidence">
                {partialAccounts} {partialAccounts === 1 ? 'account has' : 'accounts have'} unavailable checks, unassessed questions, or incomplete evidence.
                Review coverage in the account table.
              </Alert>
            )}
            <div className="report-glance-grid">
              <div className="report-glance-item">
                <Stat label="Accounts assessed" value={`${countText(summary.assessedAccounts)} / ${countText(summary.totalAccounts)}`} detail="Across this scan" />
              </div>
              <div className="report-glance-item">
                <Stat label="Accounts with scores" value={countText(summary.scoredAccounts)} detail="Included in the average" />
              </div>
              <div className="report-glance-item">
                <Stat label="Partial evidence" value={countText(partialAccounts)} detail="Accounts needing review" />
              </div>
              <div className="report-glance-item">
                <Stat label="Failed accounts" value={countText(summary.failedAccounts)} detail={summary.failedAccounts > 0 ? 'Review status below' : 'No failed accounts'} />
              </div>
            </div>
            <p className="report-summary-note">
              Aggregate scores include assessed accounts only. The account table lists failed accounts and evidence gaps.
            </p>
          </SpaceBetween>
        </Container>
        <Container header={<Header variant="h2">Category averages</Header>}>
          <BarChart
            series={[{ title: 'Average score', type: 'bar', data: categoryScores }]}
            xDomain={categories.map(category => category.label)}
            yDomain={[0, 4]}
            xScaleType="categorical"
            xTitle="Category"
            yTitle="Average maturity"
            yTickFormatter={value => Number.isInteger(value) ? String(value) : value.toFixed(1)}
            height={320}
            hideFilter
            ariaLabel="Organization category averages"
            ariaDescription="Average maturity score in each category for assessed accounts. Maturity levels are 1 through 4; the chart axis starts at 0 as a visual baseline."
            i18nStrings={CHART_STRINGS}
            empty={<Box>No category scores are available.</Box>}
          />
        </Container>
        <Table
          items={categories}
          trackBy="id"
          wrapLines
          header={<Header variant="h2">Category score ranges</Header>}
          columnDefinitions={[
            { id: 'category', header: 'Category', cell: item => item.label },
            { id: 'average', header: 'Average', cell: item => scoreText(item.score, hasScores) },
            { id: 'min', header: 'Minimum', cell: item => scoreText(item.min, hasScores) },
            { id: 'max', header: 'Maximum', cell: item => scoreText(item.max, hasScores) }
          ]}
          empty={<Box>No categories are available.</Box>}
        />
        <OrganizationAccountsTable accounts={accounts} />
        <AssessmentMethodology organization />
      </SpaceBetween>
    </main>
  );
}

function ErrorView({ message }: { message: string }) {
  return <main id="report-start" className="report-shell"><Alert type="error" header="Report could not be displayed">{message}</Alert></main>;
}

function ReportApplication({ report, initialMode }: { report: Report; initialMode: Mode }) {
  const [mode, setMode] = useState(initialMode);
  const nextMode = mode === Mode.Dark ? Mode.Light : Mode.Dark;

  function toggleMode() {
    applyMode(nextMode);
    try {
      window.localStorage.setItem(MODE_STORAGE_KEY, nextMode);
    } catch {
      // Storage is optional for reports opened directly from disk.
    }
    setMode(nextMode);
  }

  const nextModeLabel = nextMode === Mode.Light ? 'light' : 'dark';
  return (
    <>
      <div id="report-top-navigation">
        <TopNavigation
          identity={{ title: 'AWS Observability Assessment', href: '#report-start' }}
          utilities={[{
            type: 'button',
            iconSvg: <ModeIcon targetMode={nextMode} />,
            ariaLabel: `Switch to ${nextModeLabel} mode`,
            onClick: toggleMode
          }]}
          i18nStrings={{
            overflowMenuTriggerText: 'More actions',
            overflowMenuTitleText: 'Actions',
            overflowMenuDismissIconAriaLabel: 'Close menu'
          }}
        />
      </div>
      {report.reportType === 'organization'
        ? <OrganizationView report={report} />
        : <SingleAccountView report={report} />}
    </>
  );
}

function mount() {
  let root = document.getElementById('root');
  if (!root) {
    root = document.createElement('div');
    root.id = 'root';
    document.body.appendChild(root);
  }
  try {
    const report = parseReport();
    const initialMode = preferredMode();
    applyMode(initialMode);
    createRoot(root).render(<ReportApplication report={report} initialMode={initialMode} />);
  } catch (error) {
    createRoot(root).render(<ErrorView message={error instanceof Error ? error.message : 'Unknown report error.'} />);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mount, { once: true });
} else {
  mount();
}
