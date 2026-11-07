"""Provider preflight results shared by validation and listener startup."""
from __future__ import annotations

from deceive.providers import Message, ModelResult, Provider, ProviderError


class PreflightError(ValueError):
    def __init__(self, report: dict):
        self.report = report
        super().__init__('Live provider preflight failed; inspect the sanitized check results')


PROBE = [
    Message('system', 'This is an operator connectivity check. Reply with a short plain-text acknowledgement. '
            'No tools, external actions, simulated device activity or conversation history are involved.'),
    Message('user', 'Reply with: ready'),
]


async def probe(provider: Provider, maximum: int) -> ModelResult:
    result = await provider.complete(list(PROBE))
    if not isinstance(result, ModelResult) or not isinstance(result.text, str) or not result.text.strip():
        raise ProviderError('Provider returned no usable text during preflight')
    if len(result.text.encode()) > maximum:
        raise ProviderError('Provider preflight response exceeds the configured output limit')
    return result
