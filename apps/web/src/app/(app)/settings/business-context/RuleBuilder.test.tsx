/**
 * The builder may only suggest fields that resolve on the fused alert, and
 * only operators the engines implement.
 *
 * The canonical field list is pinned twice — here and in the api suite's
 * `test_rule_vocabulary_resolves.py`, which resolves these same literals
 * against the fused-alert shape through the real engine resolver. Two copies,
 * one assertion each: drift reds one of them.
 *
 * The operator half pins `ne` (the engines' term). The builder used to offer
 * `neq`, which neither engine implements — a "not equals" clause silently
 * never matched.
 */

import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';

import { RuleBuilder } from './RuleBuilder';

const SOURCE = readFileSync(join(__dirname, 'RuleBuilder.tsx'), 'utf8');

const CANONICAL_FIELDS = [
  'severity',
  'source',
  'hostname',
  'username',
  'src_ip',
  'dst_ip',
  'domain',
  'tags',
  'risk_score',
  'raw_event.env',
];

// services/agents/app/workers/business_context.py::_cmp and
// services/api/app/services/business_context/engine.py::_eval_op.
const ENGINE_OPS = new Set([
  'eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'contains',
  'startswith', 'endswith', 'in', 'not_in', 'exists', 'not_exists',
]);

function extractArray(name: string): string[] {
  const match = SOURCE.match(new RegExp(`const ${name}[^=]*= \\[([^;]*?)\\];`, 's'));
  if (!match) throw new Error(`${name} not found in RuleBuilder.tsx`);
  return [...match[1].matchAll(/["']([^"']+)["']/g)].map((m) => m[1]);
}

describe('RuleBuilder vocabulary', () => {
  it('suggests exactly the canonical fused-alert fields', () => {
    expect(extractArray('FIELD_SUGGESTIONS')).toEqual(CANONICAL_FIELDS);
  });

  it('offers only operators the engines implement', () => {
    const opValues = [...SOURCE.matchAll(/\{ value: ["']([a-z_]+)["'], label:/g)].map((m) => m[1]);
    expect(opValues.length).toBeGreaterThan(0);
    for (const op of opValues) {
      expect(ENGINE_OPS.has(op), `builder offers '${op}' which no engine implements`).toBe(true);
    }
  });

  it('never suggests the dead alert.-prefixed paths', () => {
    for (const field of extractArray('FIELD_SUGGESTIONS')) {
      expect(field.startsWith('alert.')).toBe(false);
    }
  });
});

describe('RuleBuilder mandatory escalation', () => {
  it('authors an escalation requirement without changing severity', () => {
    const onAppend = vi.fn();
    render(<RuleBuilder onAppend={onAppend} />);
    fireEvent.change(screen.getByLabelText('Rule ID'), { target: { value: 'must-review' } });
    fireEvent.change(screen.getByLabelText('Field'), { target: { value: 'source' } });
    fireEvent.change(screen.getByLabelText('Value'), { target: { value: 'fixture-source' } });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Require escalation' }));
    fireEvent.click(screen.getByRole('button', { name: 'Append rule to editor' }));

    expect(onAppend).toHaveBeenCalledOnce();
    const yaml = onAppend.mock.calls[0][0] as string;
    expect(yaml).toContain('require_escalation: true');
    expect(yaml).not.toContain('set_severity:');
    expect(yaml).not.toContain('suppress: true');
  });

  it('keeps mandatory escalation and suppression mutually exclusive', () => {
    render(<RuleBuilder onAppend={vi.fn()} />);
    const escalation = screen.getByRole('checkbox', { name: 'Require escalation' });
    const suppression = screen.getByRole('checkbox', { name: 'Suppress matching alerts' });

    fireEvent.click(escalation);
    expect(suppression).toBeDisabled();
    fireEvent.click(escalation);
    expect(suppression).toBeEnabled();
    fireEvent.click(suppression);
    expect(escalation).toBeDisabled();
  });
});
