# Contributing

Open an issue describing the detection hypothesis, data source and expected behavior. Use synthetic data only. For a pull request, update the JSON rule, add positive and negative scenarios, document false positives and blind spots, and run `python -m unittest discover -s tests -v`.

Threshold changes need boundary and grouping tests. Explain any change to the expected demo output; never regenerate a golden file solely to make a failing test pass. Keep dependencies at zero unless a concrete use case justifies one. Avoid broad allowlists and unsupported claims of production effectiveness.
