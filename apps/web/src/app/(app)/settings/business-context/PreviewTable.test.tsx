import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { PreviewRow } from './client';
import { PreviewTable } from './PreviewTable';

const ROW: PreviewRow = {
  alert_id: 'synthetic-alert',
  matched_rule_ids: ['must-investigate'],
  before: { severity: 'medium', require_escalation: false, escalation_rule_ids: [] },
  after: { severity: 'critical', require_escalation: true, escalation_rule_ids: ['must-investigate'] },
  suppressed: false,
  changed: true,
};

describe('Business context escalation preview', () => {
  it('shows the enforced requirement and the rules that require it', () => {
    render(<PreviewTable rows={[ROW]} />);
    expect(screen.getByText('escalation required')).toHaveAttribute(
      'title',
      'Required by: must-investigate',
    );
    expect(screen.queryByText('suppressed')).not.toBeInTheDocument();
    expect(screen.queryByText('modified')).not.toBeInTheDocument();
  });

  it('does not label an ordinary severity change as required escalation', () => {
    render(<PreviewTable rows={[{
      ...ROW,
      after: { severity: 'critical', require_escalation: false, escalation_rule_ids: [] },
    }]} />);
    expect(screen.getByText('modified')).toBeInTheDocument();
    expect(screen.queryByText('escalation required')).not.toBeInTheDocument();
  });
});
