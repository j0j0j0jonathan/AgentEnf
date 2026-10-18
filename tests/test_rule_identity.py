"""Stable attribution survives label stripping without changing the policy guard."""
import copy
from pathlib import Path
import pytest
import yaml
from experiments.release_candidate.rule_identity import entries, uniquify, VERDICT

ROOT=Path(__file__).resolve().parents[1]

def group(name,label,action='Approve',category='shared'):
 return {'id':name,'mfotl':'{"'+label+'"}{ALWAYS (FORALL t. P(t) IMPLIES:R '+action+'(t, "tool", "'+category+'"))}'}

def test_different_rules_and_different_actions_never_share_category():
 p={'policies':[group('a','one'),group('a2','two','Block'),group('b','same'),group('c','same')]}
 before=copy.deepcopy(p); changes=uniquify(p)
 assert len(changes)==4
 assert [m[2] for _,_,m in entries(p)]==['one','two','b__same','c__same']
 assert uniquify(p)==[]
 for a,b in zip(before['policies'],p['policies']):
  strip=lambda s:VERDICT.sub(lambda m:m[1]+'CATEGORY'+m[3],s)
  assert strip(a['mfotl'])==strip(b['mfotl'])

@pytest.mark.parametrize('name',['release-candidate','optimized-v1'])
def test_shipped_candidate_categories_are_unique_and_have_migrations(name):
 p=yaml.safe_load((ROOT/f'examples/presets/{name}.yaml').read_text())
 pairs=[((g['id'],label),m[2]) for g,label,m in entries(p)]
 assert len({owner for owner,_ in pairs})==len(pairs)
 assert len({cat for _,cat in pairs})==len(pairs)
 assert p['meta']['verdict_category_migrations']
 assert uniquify(copy.deepcopy(p))==[]

def test_collision_with_existing_unrenamed_category_is_rejected():
 p={'policies':[group('a','one'),group('b','two'),group('c','three',category='one')]}
 with pytest.raises(ValueError,match='collision'):uniquify(p)
