# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.


## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment


## Contributing via Pull Requests
Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the `main` branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work — we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code, it will be hard for us to focus on your change.
3. Run the relevant local validation commands below.
4. Commit to your fork using clear commit messages.
5. Send us a pull request, answering any default questions in the pull request interface.
6. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

## Local validation

Use Python 3.12 or later. Install runtime and validation dependencies in the
same environment that runs the tests, then run the checks relevant to your
change:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt ruff cfn-lint

# Python syntax and style
python3 -m compileall -q \
  observability_assessment observability_assessment_comprehensive.py \
  scripts/scrub-sample-report.py tests
python3 -m unittest discover -s tests -v
ruff check observability_assessment observability_assessment_comprehensive.py \
  scripts/scrub-sample-report.py tests
ruff format --check observability_assessment \
  observability_assessment_comprehensive.py scripts/scrub-sample-report.py tests

# CloudFormation
cfn-lint 1-observability-assessment-role.yaml 2-observability-assessment-codebuild.yaml

# Focused AWS validation when credentials are available
python3 observability_assessment_comprehensive.py --profile YOUR_PROFILE --single-check CHECK_ID --debug
python3 observability_assessment_comprehensive.py --profile YOUR_PROFILE --single-question QUESTION_ID --debug
```

When changing `report_ui/`, use Node.js 24 and rebuild the assets embedded in
generated reports:

```bash
npm --prefix report_ui ci
npm --prefix report_ui run typecheck
npm --prefix report_ui run build
python3 -m unittest discover -s tests -q
```

Include the updated files in `observability_assessment/reporting/assets/`
with the UI source. The Report UI pull-request workflow rebuilds them and
checks that they match the committed files. See
[report_ui/README.md](report_ui/README.md) for the embedded data contract.

Do not commit raw assessment output. Reports can contain account IDs, ARNs, resource names,
and infrastructure details. Follow [SCRUBBING.md](SCRUBBING.md) before updating committed
sample reports.

GitHub provides additional documentation on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).


## Finding contributions to work on
Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.


## Code of Conduct
This project has adopted the Amazon Open Source Code of Conduct. See
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.


## Security issue notifications
If you discover a potential security issue in this project, we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public GitHub issue.


## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.

We may ask you to sign a [Contributor License Agreement (CLA)](http://en.wikipedia.org/wiki/Contributor_License_Agreement) for larger changes.
