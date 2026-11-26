"""Bound low-level generation/linking memory by spilling complete operation batches."""

import json
import shutil
from pathlib import Path

import networkx as nx


class StreamingGraph(nx.DiGraph):
    stream = None
    linking = False
    batch_node_limit = 20000
    materializing = False

    def add_edge(self, u_of_edge, v_of_edge, **attr):
        from frontend.types import is_compute_node

        if self.stream is not None and not self.linking and hasattr(u_of_edge, '_stream_pending_encoder'):
            from frontend.custom_task import custom_compute

            attributes = u_of_edge._stream_pending_encoder
            del u_of_edge._stream_pending_encoder
            triggers = list(self.pred[v_of_edge])[:1] if v_of_edge in self else []
            self.materializing = True
            try:
                custom_compute(triggers, u_of_edge, 'encode_pt', attributes)
            finally:
                self.materializing = False
        if self.stream is not None and not self.linking and not self.materializing and len(self) >= self.batch_node_limit:
            op = v_of_edge if is_compute_node(v_of_edge) else u_of_edge
            if is_compute_node(op) and op not in self:
                self.flush()
        super().add_edge(u_of_edge, v_of_edge, **attr)

    def add_edges_from(self, ebunch_to_add, **attr):
        if self.stream is None or self.linking:
            return super().add_edges_from(ebunch_to_add, **attr)
        for edge in ebunch_to_add:
            self.add_edge(edge[0], edge[1], **{**attr, **(edge[2] if len(edge) == 3 else {})})

    def start_stream(self, output, processor):
        from frontend import types

        self.stream = _GraphFiles(output, processor)
        types.stream_node_counter = 0

    def flush(self):
        if not self:
            return
        from frontend.linker.processor_layout import apply_processor_layout, compute_runs_on_cpu
        from frontend.types import BackendDataNode, is_data_node, is_compute_node, is_custom_compute, is_key_data_node

        self.linking = True
        try:
            aliases = {}
            for node in self:
                if not is_data_node(node):
                    continue
                producers = list(self.pred[node])
                if not producers and not getattr(node, '_stream_produced', False):
                    self.stream.sources.add(node)
                if producers:
                    node._stream_produced = True
                    if not is_custom_compute(producers[0]):
                        alias = BackendDataNode.create_from(node, self.stream.processor)
                        alias.id = node.id
                        node._stream_backend_alias = alias
                aliases[node] = getattr(node, '_stream_key_backend', getattr(node, '_stream_backend_alias', node))
            self.stream.write(self, compiled=False)
            compiled = nx.relabel_nodes(self, aliases, copy=True)
            # Operand and multi-output port order is the adjacency insertion order.
            # NetworkX relabel(copy=True) reconstructs edges grouped by source.
            for node in self:
                mapped = aliases.get(node, node)
                compiled._pred[mapped] = {aliases.get(n, n): compiled._pred[mapped][aliases.get(n, n)]
                                          for n in self.pred[node]}
                compiled._succ[mapped] = {aliases.get(n, n): compiled._succ[mapped][aliases.get(n, n)]
                                          for n in self.succ[node]}
            inputs = [n for n in compiled if is_data_node(n) and not compiled.pred[n]]
            # Intermediate values stay on the backend across batches. Keeping
            # primitive tasks also preserves values referenced by future batches.
            apply_processor_layout(compiled, self.stream.processor, inputs, [])
            for node in inputs:
                if is_key_data_node(node) and not isinstance(node, BackendDataNode):
                    exported = next(compiled.successors(node))
                    abi = next(compiled.successors(exported))
                    loaded = next(compiled.successors(abi))
                    backend = next(compiled.successors(loaded))
                    node._stream_key_backend = backend
                    for bridge in (abi, backend):
                        bridge._stream_key_source = node
                        self.stream.key_bridges[bridge] = node
            for node in compiled:
                if is_compute_node(node):
                    node.on_cpu = compute_runs_on_cpu(node, self.stream.processor)
                    node.priority = 2147483647 - int(node.id.removeprefix('stream_'))
            self.stream.write(compiled, compiled=True)
            super().clear()
        finally:
            self.linking = False

    def finish_stream(self, ctx, parameter, extra_signature_fields):
        from frontend.linker import serialize_signature
        from frontend.types import is_key_data_node

        self.flush()
        missing = self.stream.sources - set(ctx.inputs)
        if missing:
            raise ValueError('Streamed graph has unbound inputs: ' + str([n.id for n in missing][:10]))
        if any(not getattr(node, '_stream_produced', False) for node in ctx.outputs):
            raise ValueError('Streamed graph has an unproduced output')
        from frontend.linker.bridge_ops import store_from_backend, import_from_abi
        from frontend.linker.processor_layout import compute_runs_on_cpu
        from frontend.types import CkksCiphertextNode, is_compute_node

        final = nx.DiGraph()
        compiled_outputs = []
        for node in ctx.outputs:
            backend = getattr(node, '_stream_backend_alias', None)
            if backend is None:
                compiled_outputs.append(node)
                continue
            handle = CkksCiphertextNode(level=node.metadata.level)
            handle.metadata = node.metadata.copy()
            concrete = store_from_backend(final, backend, self.stream.processor)
            import_from_abi(final, concrete, handle)
            compiled_outputs.append(handle)
        for node in final:
            if is_compute_node(node):
                node.on_cpu = compute_runs_on_cpu(node, self.stream.processor)
                node.priority = 2147483647 - int(node.id.removeprefix('stream_'))
        self.stream.write(final, compiled=True)
        keys = [node for node in ctx.inputs if is_key_data_node(node)]
        self.stream.finish(ctx, keys, compiled_outputs)
        output = self.stream.output
        signature = serialize_signature(ctx)
        signature.update(extra_signature_fields or {})
        for name, value in [('task_signature.json', signature), ('fhe_parameter.json', parameter.to_json_dict()),
                            ('graph_key_data.json', {n.id: n.to_json_dict() for n in keys})]:
            with (output / name).open('w') as file:
                json.dump(value, file)
        return {'streaming': True, 'batches': self.stream.batches}

    def close_stream(self):
        from frontend import types

        if self.stream is not None:
            self.stream.close()
            self.stream = None
        types.stream_node_counter = None


class _GraphFiles:
    def __init__(self, output, processor):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.processor = processor
        self.sources = set()
        self.batches = 0
        self.key_bridges = {}
        self.files = {(compiled, kind): (self.output / f'.stream-{compiled}-{kind}').open('w')
                      for compiled in (False, True) for kind in ('data', 'compute')}
        self.counts = {key: 0 for key in self.files}

    def write(self, dag, compiled):
        from frontend.types import BridgeDataNode, is_data_node, is_compute_node, is_key_data_node
        from frontend.linker.serializer import _serialize_ops_task

        for node in dag:
            if hasattr(node, '_stream_key_source'):
                continue
            if is_data_node(node) and is_key_data_node(node) and not isinstance(node, BridgeDataNode):
                # Key levels can increase in later batches. Publish their final metadata once.
                continue
            if is_data_node(node):
                flag = '_stream_compiled' if compiled else '_stream_raw'
                if getattr(node, flag, False):
                    continue
                setattr(node, flag, True)
                kind, value = 'data', node.to_json_dict()
            elif is_compute_node(node):
                kind = 'compute'
                value = _serialize_ops_task(dag, node) if compiled else node.to_json_dict(dag)
                if getattr(node, 'on_cpu', None) is not None:
                    value['on_cpu'] = node.on_cpu
                if hasattr(node, 'priority'):
                    value['priority'] = node.priority
            else:
                continue
            self.record(compiled, kind, node.id, value)
        if compiled:
            self.batches += 1

    def record(self, compiled, kind, name, value):
        key = compiled, kind
        file = self.files[key]
        if self.counts[key]:
            file.write(',')
        json.dump(name, file)
        file.write(':')
        json.dump(value, file, separators=(',', ':'))
        self.counts[key] += 1

    def finish(self, ctx, keys, compiled_outputs):
        for bridge, source in self.key_bridges.items():
            bridge.metadata.level = source.metadata.level
            bridge.sp_level = source.sp_level
            self.record(True, 'data', bridge.id, bridge.to_json_dict())
        for compiled, name in [(False, 'mega_ag.json'), (True, 'compiled_mega_ag.json')]:
            for node in keys:
                self.record(compiled, 'data', node.id, node.to_json_dict())
            with (self.output / name).open('w') as target:
                header = dict(name=ctx.name, algorithm=ctx.algorithm.value,
                              inputs=[n.id for n in ctx.inputs],
                              outputs=[n.id for n in (compiled_outputs if compiled else ctx.outputs)])
                target.write(json.dumps(header)[:-1])
                for kind in ('data', 'compute'):
                    target.write(',"' + kind + '":{')
                    source = self.files[compiled, kind]
                    source.close()
                    with Path(source.name).open('r') as reader:
                        shutil.copyfileobj(reader, target, 1024 * 1024)
                    target.write('}')
                target.write('}')
        self.close()

    def close(self):
        for file in self.files.values():
            if not file.closed:
                file.close()
            Path(file.name).unlink(missing_ok=True)
