// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import React from 'react';
import { Box, ColumnLayout, Container, Header, SpaceBetween } from '@cloudscape-design/components';

const QUESTION_LEVELS = [
  { level: 1, meaning: 'Basic or limited use of the practice, including an absence of the capability where the question measures it.' },
  { level: 2, meaning: 'Broader adoption or an additional capability beyond the first level.' },
  { level: 3, meaning: 'More advanced coverage, analysis, or operational practice.' },
  { level: 4, meaning: 'The strongest criteria defined for that question, such as proactive insights or demonstrated business value.' }
];

const SCORE_BANDS = [
  { label: 'Reactive', range: '1.0 to below 2.0' },
  { label: 'Proactive', range: '2.0 to below 3.5' },
  { label: 'Autonomous', range: '3.5 to 4.0' }
];

export function AssessmentMethodology({ organization = false }: { organization?: boolean }) {
  return (
    <Container header={<Header variant="h2">Assessment methodology</Header>}>
      <SpaceBetween size="l">
        <Box>
          Discovery checks collect AWS configuration evidence for 17 questions across five categories.
          Deterministic rules assign each question with evaluable evidence a maturity level from 1 to 4.
          The criteria are specific to each question.
        </Box>
        <div>
          <Header variant="h3">What the question levels mean</Header>
          <ColumnLayout columns={2} variant="text-grid">
            {QUESTION_LEVELS.map(({ level, meaning }) => (
              <div key={level}>
                <Box variant="h4">Level {level}</Box>
                <Box>{meaning}</Box>
              </div>
            ))}
          </ColumnLayout>
          <Box color="text-body-secondary" margin={{ top: 's' }}>
            {organization
              ? 'Each account report shows the exact level descriptions and discovery evidence for every question.'
              : 'Expand a question above to see its exact level descriptions, selected level, and discovery evidence.'}
          </Box>
        </div>
        <div>
          <Header variant="h3">How scores are derived</Header>
          <SpaceBetween size="xs">
            <Box>
              A category score is the arithmetic mean of its assessed question levels.
              The overall account score is the arithmetic mean of all assessed question levels, with each question weighted equally.
            </Box>
            <Box>
              Questions without evaluable evidence are marked Not assessed and excluded from those averages.
              If no questions can be assessed, the score is N/A.
            </Box>
            <Box>
              Unavailable or incomplete discovery evidence is flagged in the report.
              Scores based on partial evidence may understate actual maturity.
            </Box>
            {organization && (
              <Box>
                Organization averages use the account scores of successfully assessed accounts with at least one scored question.
                Organization category averages use the available per-account category scores.
                Failed accounts and accounts without a score are excluded; the range shows the lowest and highest included account scores.
              </Box>
            )}
          </SpaceBetween>
        </div>
        <div>
          <Header variant="h3">Overall maturity bands</Header>
          <Box margin={{ bottom: 's' }}>
            The overall maturity label comes from the averaged score using these bands:
          </Box>
          <ColumnLayout columns={3} variant="text-grid">
            {SCORE_BANDS.map(({ label, range }) => (
              <div key={label}>
                <Box variant="h4">{label}</Box>
                <Box>{range}</Box>
              </div>
            ))}
          </ColumnLayout>
        </div>
        <Box color="text-body-secondary">
          Most discovery checks cover the selected AWS Region, and some inspect bounded samples.
          These scores describe the available evidence at report generation time, not an exhaustive inventory.
        </Box>
      </SpaceBetween>
    </Container>
  );
}
