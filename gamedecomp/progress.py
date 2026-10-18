"""Count completed function units without treating compilation as correctness."""
import copy
from gamedecomp.semantic import candidate_is_usable


def normalize_progress(value):
    """Accept only bounded, internally consistent child-process telemetry."""
    if not isinstance(value, dict):
        return None
    keys = ('processed_units', 'compiled_units', 'ai_compiled_units',
            'tested_units', 'rejected_units', 'unknown_units')
    total = value.get('total_units')
    if total is not None and (type(total) is not int or not 0 <= total <= 100000):
        return None
    if any(type(value.get(key)) is not int or not 0 <= value[key] <= 100000 for key in keys):
        return None
    processed = value['processed_units']
    if sum(value[key] for key in ('tested_units', 'rejected_units', 'unknown_units')) != processed:
        return None
    if total is None and any(value[key] for key in keys):
        return None
    if total is not None and any(value[key] > total for key in keys):
        return None
    stages = {'INGEST', 'ANALYSIS', 'CONTEXT', 'COMPILATION', 'RECONSTRUCTION',
              'VALIDATION', 'PROCESSING', 'EXPORT', 'COMPLETE'}
    if value.get('stage') not in stages:
        return None
    active = value.get('active_units', [])
    if not isinstance(active, list) or len(active) > 8:
        return None
    units = []
    for unit in active:
        if not isinstance(unit, dict) or unit.get('stage') not in stages:
            return None
        if any(not isinstance(unit.get(key), str) or len(unit[key]) > 128 for key in ('id', 'name')):
            return None
        units.append({key: unit[key] for key in ('id', 'name', 'stage')})
    return dict({key: value[key] for key in keys}, total_units=total,
                stage=value['stage'], active_units=units)


class ProgressTracker:
    def __init__(self, callback=None):
        if callback is not None and not callable(callback):
            raise TypeError('progress_callback must be callable or None')
        self.callback = callback
        self.total = None
        self.units = {}
        self.active = {}
        self.counts = dict.fromkeys(('processed_units', 'compiled_units', 'ai_compiled_units',
                                    'tested_units', 'rejected_units', 'unknown_units'), 0)

    def emit(self, stage, phase):
        if self.callback is None:
            return
        snapshot = dict(self.counts, total_units=self.total, stage=stage,
                        active_units=list(self.active.values())[:8])
        try:
            self.callback(copy.deepcopy({'phase': phase, 'progress': snapshot}))
        except Exception:
            # An optional display observer cannot alter or abort analysis.
            self.callback = None

    def configure(self, functions):
        self.total = len(functions)
        self.emit('ANALYSIS', 'Function discovery complete')

    def start(self, function, stage):
        self.active[function.id] = {'id': str(function.id)[:128], 'name': str(function.name)[:128], 'stage': stage}
        self.emit(stage, {'CONTEXT': 'Building binary evidence', 'COMPILATION': 'Compiling recovered units',
                          'RECONSTRUCTION': 'Reconstructing with the selected LLM',
                          'VALIDATION': 'Checking candidate behavior'}.get(stage, stage))

    def observe(self, function, compilation, candidate, *, done=False):
        old = self.units.get(function.id, dict.fromkeys(self.counts, 0))
        processed = bool(done or old['processed_units'])
        usable = candidate_is_usable(candidate)
        semantic = (candidate or {}).get('semantic_status')
        tested = processed and usable and semantic == 'TESTED'
        rejected = processed and semantic == 'DISPROVED'
        new = {'processed_units': int(processed),
               'compiled_units': int(usable or compilation.get('status') == 'COMPILED'),
               'ai_compiled_units': int((candidate or {}).get('compilation', {}).get('status') == 'COMPILED'),
               'tested_units': int(tested), 'rejected_units': int(rejected),
               'unknown_units': int(processed and not tested and not rejected)}
        for key in self.counts:
            self.counts[key] += new[key] - old[key]
        self.units[function.id] = new
        if done:
            self.active.pop(function.id, None)
        self.emit('PROCESSING', 'Processing function units')
