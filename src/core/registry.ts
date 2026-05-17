import { Analyzer, Match } from './types'

export class AnalyzerRegistry {
  private readonly analyzers = new Map<string, Analyzer>()

  register(analyzer: Analyzer): void {
    if (this.analyzers.has(analyzer.id)) {
      throw new Error(`Analyzer already registered: ${analyzer.id}`)
    }
    this.analyzers.set(analyzer.id, analyzer)
  }

  get(id: string): Analyzer | undefined {
    return this.analyzers.get(id)
  }

  list(): Analyzer[] {
    return Array.from(this.analyzers.values())
  }

  detectAll(text: string): Array<{ analyzer: Analyzer; match: Match }> {
    const results: Array<{ analyzer: Analyzer; match: Match }> = []
    for (const analyzer of this.analyzers.values()) {
      for (const match of analyzer.detect(text)) {
        results.push({ analyzer, match })
      }
    }
    return results
  }
}
