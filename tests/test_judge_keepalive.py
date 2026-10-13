from instrlib import tool_judge as j

def test_keepalive_reuses_client_and_preserves_request(monkeypatch):
 calls=[];created=[]
 class Client:
  def __init__(self):created.append(self)
  def post(self,url,**kw):calls.append((url,kw));return 'response'
  def close(self):pass
 monkeypatch.setenv('ENFGUARD_TOOL_JUDGE_KEEPALIVE','1')
 monkeypatch.setattr(j,'_KEEPALIVE_CLIENT',None)
 monkeypatch.setattr(j.httpx,'Client',Client)
 args=dict(headers={'x-test':'value'},json={'messages':['unaltered']},timeout=17)
 assert j._post_json('https://example.invalid',**args)=='response'
 assert j._post_json('https://example.invalid',**args)=='response'
 assert len(created)==1 and calls==[('https://example.invalid',args)]*2

def test_disabled_keepalive_keeps_existing_transport(monkeypatch):
 monkeypatch.delenv('ENFGUARD_TOOL_JUDGE_KEEPALIVE',raising=False)
 monkeypatch.setattr(j.httpx,'post',lambda url,**kw:(url,kw))
 assert j._post_json('url',timeout=3)==('url',{'timeout':3})
