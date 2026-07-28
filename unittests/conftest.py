# Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0


def pytest_configure(config):
    config.addinivalue_line('markers', 'min_level(n): minimum level (inclusive) for lv parametrization')
    config.addinivalue_line('markers', 'at_level(n): fixed level value for lv parametrization')
    config.addinivalue_line('markers', 'at_max_level: use param.max_level as lv for each param')


def pytest_generate_tests(metafunc):
    """Dynamically parametrize 'param' and optionally 'lv' for FHE test modules.

    Test methods that iterate over levels should:
      1. Add 'lv' to their signature: def test_xxx(self, param, lv)
      2. Decorate with @pytest.mark.min_level(N) to set the start level (default 0)

    Test IDs will be formatted as: <param_tag>-lv<N>
    """
    module = metafunc.module
    params_list = getattr(module, 'BFV_PARAMS', None) or getattr(module, 'CKKS_PARAMS', None)
    if params_list is None:
        return

    param_tag_fn = getattr(module, '_param_tag', None)
    has_param = 'param' in metafunc.fixturenames
    has_lv = 'lv' in metafunc.fixturenames

    if not has_param:
        return

    if has_lv:
        at_marker = metafunc.definition.get_closest_marker('at_level')
        min_marker = metafunc.definition.get_closest_marker('min_level')

        if at_marker:
            fixed_lv = at_marker.args[0]
            combos = [(p, fixed_lv) for p in params_list]
            ids = [f'{param_tag_fn(p) if param_tag_fn else repr(p)}-lv{fixed_lv}' for p in params_list]
        elif metafunc.definition.get_closest_marker('at_max_level'):
            combos = [(p, p.max_level) for p in params_list]
            ids = [f'{param_tag_fn(p) if param_tag_fn else repr(p)}-lv{p.max_level}' for p in params_list]
        else:
            min_lv = min_marker.args[0] if min_marker else 0
            combos = []
            ids = []
            for p in params_list:
                for lv in range(min_lv, p.max_level + 1):
                    combos.append((p, lv))
                    tag = param_tag_fn(p) if param_tag_fn else repr(p)
                    ids.append(f'{tag}-lv{lv}')

        metafunc.parametrize('param,lv', combos, ids=ids)
    else:
        ids = [param_tag_fn(p) for p in params_list] if param_tag_fn else None
        metafunc.parametrize('param', params_list, ids=ids)
