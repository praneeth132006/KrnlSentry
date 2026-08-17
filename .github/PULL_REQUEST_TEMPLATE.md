## What this changes

<!-- One or two sentences. If it fixes an issue, "Fixes #123". -->

## Why

<!-- The reasoning. This project's code comments explain *why* rather than
     *what*; PR descriptions should do the same. -->

## Checklist

- [ ] `make docker-make TARGET=all` passes (generate, build, test)
- [ ] `gofmt -l .` prints nothing
- [ ] New or changed behaviour has tests, **including negative cases**
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)

### If you touched `bpf/` or `detect/`

- [ ] Ran the end-to-end scenarios in a privileged container:
      `docker run --rm --privileged -v "$PWD":/src krnlsentry-dev bash -c "make build && ./test/run-all.sh"`
- [ ] Enum values were **appended**, never renumbered
- [ ] Any new limitation or bypass is documented in the README

## Anything reviewers should look at closely

<!-- Verifier arguments you are unsure about, a rule whose false-positive rate
     you cannot judge, a trade-off you made and want a second opinion on. -->
