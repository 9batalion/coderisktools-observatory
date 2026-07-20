# Architecture

The planned flow is target registry → safe acquisition → OSS adapters → normalized findings → publication policy → report builder → operator review → publication PR → validation → manual merge → static reports. The basic pipeline never executes target code.

The repository is code-first. Public report data belongs in `coderisktools-observatory-reports`; this repository must not silently mutate published report data.
