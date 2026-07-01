name: Bug Report
description: Create a report to help us improve CodeShield AI.
labels: [bug]
body:
  - type: markdown
    attributes:
      value: Please provide a detailed description of the bug and how to reproduce it.
  - type: textarea
    id: description
    attributes:
      label: Description
      placeholder: What goes wrong?
    validations:
      required: true
  - type: textarea
    id: steps
    attributes:
      label: Steps to Reproduce
      placeholder: |
        1. Go to URL input
        2. Paste URL
        3. Trigger scan
    validations:
      required: true
