# ZangoPE

Another library for parsing PE information.
To load a PE, just run:

```python
from zangope import Binary
calc = Binary.load_from_path("calc.exe")
```

Manipulations of PE file format:

* Add new section ✅ 
* Extend DOS header ✅
* Inject content between sections ❌
* Remove ASLR loading ✅
* Make .text section writeable ✅