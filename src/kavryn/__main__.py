"""Allow ``python -m kavryn`` without adding another CLI implementation."""

from aegis.cli import main

raise SystemExit(main())
