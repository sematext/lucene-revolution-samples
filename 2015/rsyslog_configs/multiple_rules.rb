version=2

rule=apache_combined:%[ 
  {"type": "word", "name": "clientip"},
  {"type": "literal", "text": " "},
  {"type": "word", "name": "ident"},
  {"type": "literal", "text": " "},
  {"type": "word", "name": "auth"},
  {"type": "literal", "text": " ["},
  {"type": "char-to", "name": "timestamp", "extradata": "]"},
  {"type": "literal", "text": "] \""},
  {"type": "word", "name": "verb"},
  {"type": "literal", "text": " "},
  {"type": "word", "name": "request"},
  {"type": "literal", "text": " HTTP/"},
  {"type": "float", "name": "httpversion"},
  {"type": "literal", "text": "\" "},
  {"type": "number", "name": "response"},
  {"type": "literal", "text": " "},
  {"type": "number", "name": "bytes"},
  {"type": "literal", "text": " \""},
  {"type": "char-to", "name": "referrer", "extradata": "\""},
  {"type": "literal", "text": "\" \""},
  {"type": "char-to", "name": "agent", "extradata": "\""},
  {"type": "literal", "text": "\""},
  {"type": "rest", "name": "blob"}
]%
#annotate=apache_combined:+tags="apache_combined"

rule=apache_common:%[
  {"type": "word", "name": "clientip"},
  {"type": "literal", "text": " "},
  {"type": "word", "name": "ident"},
  {"type": "literal", "text": " "},
  {"type": "word", "name": "auth"},
  {"type": "literal", "text": " ["},
  {"type": "char-to", "name": "timestamp", "extradata": "]"},
  {"type": "literal", "text": "] \""},
  {"type": "word", "name": "verb"},
  {"type": "literal", "text": " "},
  {"type": "word", "name": "request"},
  {"type": "literal", "text": " HTTP/"},
  {"type": "float", "name": "httpversion"},
  {"type": "literal", "text": "\" "},
  {"type": "number", "name": "response"},
  {"type": "literal", "text": " "},
  {"type": "number", "name": "bytes"},
  {"type": "rest", "name": "blob", "priority": 65535}
]%

rule=:%root:json%

rule=:%root:cee-syslog%

rule=:%[
  {"type": "date-rfc5424", "name": "timestamp"},
  {"type": "literal", "text": " "},
  {"type": "rest", "name": "message", "priority": 65534}
]%

# end
