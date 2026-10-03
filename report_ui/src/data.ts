// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

export interface Category {
  id: string;
  label: string;
  score: number | null;
  assessedCount: number;
  totalCount: number;
}

export interface Recommendation {
  title: string;
  description: string;
  url: string;
}

export interface Question {
  id: number;
  category: string;
  question: string;
  assessed: boolean;
  level: number | null;
  levelLabel: string;
  explanation: string;
  evidenceCheckIds: number[];
  unavailableCheckIds: number[];
  incompleteCheckIds: number[];
  maturityDescriptions: { level: number; description: string }[];
  recommendations: Recommendation[];
}

export interface DiscoveryCheck {
  id: number;
  name: string;
  category: string;
  status: string;
  command: string;
  evidenceText: string;
  evidenceSummary?: string;
  evidenceDetails?: string;
}

export interface SingleAccountReport {
  reportType?: 'single-account';
  meta: {
    accountId: string;
    region: string;
    generatedAt: string;
    backLink: string | null;
  };
  summary: {
    overallScore: number | null;
    maturityLevel: string;
    discoveryEvaluated: number;
    discoveryTotal: number;
    discoveryUnavailable: number;
    questionsAssessed: number;
    questionsTotal: number;
    partialQuestions: number;
  };
  categories: Category[];
  questions: Question[];
  discovery: DiscoveryCheck[];
}

export interface OrganizationCategory {
  id: string;
  label: string;
  score: number | null;
  min: number | null;
  max: number | null;
}

export interface Account {
  id: string;
  name: string | null;
  score: number | null;
  maturity: string | null;
  status: string | null;
  error: string | null;
  link: string | null;
  unavailableChecks: number | null;
  notAssessedQuestions: number | null;
  partialQuestions: number | null;
}

export interface OrganizationReport {
  reportType: 'organization';
  meta: {
    organizationId: string;
    generatedAt: string;
  };
  summary: {
    averageScore: number | null;
    minScore: number | null;
    maxScore: number | null;
    maturityLevel: string;
    bestMaturityLevel: string;
    assessedAccounts: number;
    scoredAccounts: number;
    totalAccounts: number;
    failedAccounts: number;
  };
  categories: OrganizationCategory[];
  accounts: Account[];
}

export type Report = SingleAccountReport | OrganizationReport;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function parseReport(): Report {
  const script = document.getElementById('assessment-data');
  if (!script || script.tagName !== 'SCRIPT' || script.getAttribute('type') !== 'application/json') {
    throw new Error('Embedded assessment data was not found.');
  }

  let data: unknown;
  try {
    data = JSON.parse(script.textContent || '');
  } catch {
    throw new Error('Embedded assessment data is not valid JSON.');
  }

  if (!isObject(data) || !isObject(data.meta) || !isObject(data.summary) || !Array.isArray(data.categories)) {
    throw new Error('Embedded assessment data is missing required report sections.');
  }
  if (data.reportType === 'organization') {
    if (!Array.isArray(data.accounts)) {
      throw new Error('Organization assessment data is missing accounts.');
    }
    return data as unknown as OrganizationReport;
  }
  if (data.reportType !== undefined && data.reportType !== 'single-account') {
    throw new Error('Embedded assessment data has an unsupported report type.');
  }
  if (!Array.isArray(data.questions) || !Array.isArray(data.discovery)) {
    throw new Error('Single-account assessment data is missing questions or discovery checks.');
  }
  return data as unknown as SingleAccountReport;
}

export function scoreText(score: number | null | undefined, available = true): string {
  return available && typeof score === 'number' && Number.isFinite(score)
    ? `${score.toFixed(1)} / 4`
    : 'N/A';
}

export function countText(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : 'N/A';
}

export function timeText(value: string | null | undefined): string {
  if (!value) return 'N/A';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function safeHref(value: string | null | undefined): string | undefined {
  if (!value || !value.trim()) return undefined;
  const href = value.trim();
  if (/^https?:\/\//i.test(href)) return href;
  return /^[A-Za-z0-9._-]+\.html$/.test(href) ? href : undefined;
}

export function isExternalHref(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

export function matchesCategory(questionCategory: string, category: Pick<Category, 'id' | 'label'>): boolean {
  const normalize = (value: string) => value.toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]/g, '');
  return normalize(questionCategory) === normalize(category.label) ||
    normalize(questionCategory) === normalize(category.id);
}
