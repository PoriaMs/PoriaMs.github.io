# 愿天堂没有Java之常见API


**JavaSE 笔记（三）**

<!--more-->

> Java 是一门非常严谨的语言

#### API 概述

##### 认识一下嘛

- `API (Application Programming interface)`应用程序编程接口
- 简单来说就是 Java 已经写好的一些方法，我们只需要拿过来调用即可

#### Object

##### 认识一下嘛

- Object 类的方法是一切子类对象都可以直接索引使用的

##### 常用方法

| 方法名                            | 说明                                                         |
| :-------------------------------- | :----------------------------------------------------------- |
| `public String toString()`        | 默认是返回当前对象在堆内存中的地址信息：类的全限名@内存地址  |
| `public boolean equals(Object o)` | 默认是比较当前对象与另一个对象的地址是否相同，相同返回true，不同返回false |

##### toString

- 父类`toString()`方法存在的意义就是为了被子类重写，以便返回对象的内容信息，而不是地址信息
- 子类重写之后，直接输出对象就可以看到对象的数据内容，更有意义

##### equals

- `==`可以比较两个对象的地址是否相同，但是不能去比较对象的属性
- 父类equals方法存在的意义就是为了被子类重写，以便子类自己来定制比较规则

#### Objects

##### 认识一下嘛

- Objects 类是一个工具类，提供了一些方法去完成一些功能

##### 常见方法

| 方法名                                             | 说明                                                         |
| -------------------------------------------------- | ------------------------------------------------------------ |
| `public static boolean equals(Object a, Object b)` | 比较两个对象的，底层会先进行非空判断，从而可以避免空指针异常。再进行equals比较 |
| `public static boolean isNull(Object obj) `        | 判断变量是否为null ,为null返回true ,反之                     |

#### StringBuilder

##### 认识一下

- StringBuilder是一个可变的**字符串类**，可以把它看成是一个对象容器

- 提高字符串操作效率，比如拼接、修改

##### 构造器

| 名称                               | 说明                                           |
| ---------------------------------- | ---------------------------------------------- |
| `public StringBuilder()`           | 创建一个空白的可变的字符串对象，不包含任何内容 |
| `public StringBuilder(String str)` | 创建一个指定字符串内容的可变字符串对象         |

##### 常见方法

| 方法名称                                | 说明                                                |
| --------------------------------------- | --------------------------------------------------- |
| `public StringBuilder append(任意类型)` | 添加数据并返回StringBuilder对象本身                 |
| `public StringBuilder reverse()`        | 将对象的内容反转                                    |
| `public int length()`                   | 返回对象内容长度                                    |
| `public String toString()`              | 通过toString()就可以实现把StringBuilder转换为String |

#### Math

##### 认识一下嘛

- 包含执行基本数字运算的方法，没有公开的构造器
- 成员都是静态的，直接通过类名来索引

##### 常用方法

| 方法名                                        | 说明                                  |
| --------------------------------------------- | ------------------------------------- |
| `public static int abs(int a)`                | 获取参数绝对值                        |
| `public static double  ceil(double a)`        | 向上取整                              |
| `public static double  floor(double a)`       | 向下取整                              |
| `public static int round(float a)`            | 四舍五入                              |
| `public static int max(int a,int b)`          | 获取两个int值中的较大值               |
| `public static double pow(double a,double b)` | 返回a的b次幂的值                      |
| `public static double random()`               | 返回值为double的随机值，范围[0.0,1.0) |

#### System

##### 认识一下嘛

- System 也是一个工具类，代表了当前系统，提供一些与系统相关的方法

##### 常用方法

| 方法名                                                       | 说明                                         |
| ------------------------------------------------------------ | -------------------------------------------- |
| `public  static void exit(int status)`                       | 终止当前运行的 Java 虚拟机，非零表示异常终止 |
| `public  static long currentTimeMillis()`                    | 返回当前系统的时间毫秒值形式                 |
| `public  static void arraycopy(数据源数组, 起始索引, 目的地数组, 起始索引, 拷贝个数)` | 数组拷贝                                     |

#### BigDecimal

##### 认识一下嘛

- 浮点型运算的时候直接`+-*/`可能会出现数据失真，用于解决浮点型运算精度失真的问题

- 调用方法封装浮点型数据

  ```java
  BigDecimal b1 = BigDecimal.valueOf(0.1);
  ```

##### 常用方法

| 方法名                                                       | 说明 |
| ------------------------------------------------------------ | ---- |
| `public BigDecimal add(BigDecimal b)`                        | 加法 |
| `public BigDecimal subtract(BigDecimal b)`                   | 减法 |
| `public BigDecimal multiply(BigDecimal b)`                   | 乘法 |
| `public BigDecimal divide(BigDecimal b)`                     | 除法 |
| `public BigDecimal divide (另一个BigDecimal对象，精确几位，舍入模式)` | 除法 |

- 对舍入模式的说明

  ```java
  BigDecimal.ROUND_UP  进一法
  BigDecimal.ROUND_FLOOR 去尾法
  BigDecimal.ROUND_HALF_UP 四舍五入
  ```

#### LocalDate、LocalTime、LocalDateTime

##### 认识一下嘛

- 他们 分别表示日期，时间，日期时间对象，他们的类的实例是不可变的对象
- 三者构建对象和 API 都是通用的

##### 构造器

| 方法名                        | 说明                            |
| ----------------------------- | ------------------------------- |
| `public static Xxxx now();`   | 静态方法，根据当前时间创建对象  |
| `public static Xxxx of(...);` | 静态方法，指定日期/时间创建对象 |

##### 常见方法

| 方法名                            | 说明               |
| --------------------------------- | ------------------ |
| `public int geYear()`             | 获取年             |
| `public int getMonthValue()`      | 获取月份（1-12）   |
| `Public int getDayOfMonth()`      | 获取月中第几天乘法 |
| `Public int getDayOfYear()`       | 获取年中第几天     |
| `Public DayOfWeek getDayOfWeek()` | 获取星期           |

#### 包装类

##### 认识一下嘛

- Java 为了实现一切皆对象，为8种基本类型提供了对应的引用类型
- 集合和泛型也只能支持包装类型，不支持基本数据类型

##### 对应关系

| 基本数据类型 | 引用数据类型 |
| ------------ | ------------ |
| byte         | Byte         |
| short        | Short        |
| int          | Integer      |
| long         | Long         |
| char         | Character    |
| float        | Float        |
| double       | Double       |
| boolean      | Boolean      |

##### 特性

- 自动装箱：基本数据类型可以直接赋值给包装类型
- 自动拆箱：包装类型可以直接赋值给基本数据类型

##### 特有功能

- 包装类变量默认值为`null`

- 可以把基本类型数据转化为字符串类型

  ```java
  Integer.toString(int类型的值);
  ```

- 可以把字符串类型转化为真实的数据类型

  ```java
  Integer.parseInt("字符串类型的整数");
  Double.parseDouble("字符串类型的小数");
  ```

#### 正则表达式

##### 认识一下嘛

- 正则表达式可以用一些规定的字符来制定规则，并用来校验数据格式的合法性

##### 使用详解

- 字符串对象提供了匹配正则表达的方法

  ```java
  public boolean matches(String regex)
  ```

- 字符类（默认只匹配一个字符）

  ```java
  [abc]	       		只能是a, b, 或c
  [^abc]	       	除了a, b, c之外的任何字符
  [a-zA-Z]       	a到z A到Z，包括（范围）
  [a-d[m-p]]	 	  a到d，或m通过p：（[a-dm-p]联合）
  [a-z&&[def]]	 	d, e, 或f(交集)
  [a-z&&[^bc]]		a到z，除了b和c：（[ad-z]减法）
  ```

- 预定义字符类（默认只匹配一个字符）

  ```java
  .			任何字符
  \d		一个数字： [0-9]
  \D		非数字： [^0-9]
  \s		一个空白字符： [ \t\n\x0B\f\r]
  \S		非空白字符： [^\s]
  \w		[a-zA-Z_0-9] 英文、数字、下划线
  \W	 	[^\w] 一个非单词字符
  ```

- 贪婪量词

  ```java
  X?					X，一次或根本不
  X*					X，零次或多次
  X+					X，一次或多次
  X {n}				X，正好n次
  X {n, }			X，至少n次
  X {n,m}			X，至少n但不超过m次
  ```

##### 用例

```java
System.out.println("a".matches("[abc]")); // true
System.out.println("z".matches("[abc]")); // false
System.out.println("ab".matches("[abc]")); // false
System.out.println("ab".matches("[abc]+")); //true
```

##### 在字符串方法中的应用

| 方法名                                                 | 说明                                                         |
| ------------------------------------------------------ | ------------------------------------------------------------ |
| `public String replaceAll(String regex,String newStr)` | 按照正则表达式匹配的内容进行替换                             |
| `public String[] split(String regex)`                  | 按照正则表达式匹配的内容进行分割字符串，反回一个字符串数组。    方法名 |

#### Arrays

##### 认识一下嘛

- 用于操作数组的工具类

##### 常见方法

| 方法名                                                       | 说明                                             |
| ------------------------------------------------------------ | ------------------------------------------------ |
| `public static String toString(类型[] a)`                    | 返回数组的内容（字符串形式）                     |
| `public  static void sort(类型[] a)`                         | 对数组进行默认升序排序                           |
| `public  static <T> void sort(类型[] a, Comparator<?  super T> c)` | 使用比较器对象自定义排序                         |
| `public  static int binarySearch(int[] a,  int key)`         | 二分搜索数组中的数据，存在返回索引，不存在返回-1 |

##### 排序方法

- 设置 Comparator 接口对应的比较器对象，定制比较规则

  - 如果认为左边数据 大于 右边数据 返回正整数
  - 如果认为左边数据 小于 右边数据 返回负整数
  - 如果认为左边数据 等于 右边数据 返回0

  ```java
  Arrays.sort(ages1, new Comparator<Integer>() {
    @Override
    public int compare(Integer o1, Integer o2) {
    // return o1 - o2; // 默认升序
    // return o2 - o1; // 降序
    }
  });
  
  // 以上代码还可简化为
  Arrays.sort(ages1, ( o1,  o2) ->  o1 - o2 );
  ```

#### Lambda

##### 认识一下嘛

- 简化匿名内部类的代码写法
- 函数式接口：首先必须是接口，其次接口中有且只有一个抽象方法，通常会伴有`@FunctionalInterface`注解
- Lambda 表达式只能简化函数式接口的匿名内部类的写法形式

##### 省略规则

- 参数类型可以省略
- 如果只有一个参数，参数类型可以省略，同时 () 也可以省略

- 如果 Lambda 表达式的方法体代码只有一行代码，可以省略大括号不写，同时要省略分号！

- 如果 Lambda 表达式的方法体代码只有一行代码，可以省略大括号不写；此时，如果这行代码是 return 语句，必须省略 return 不写，同时也必须省略 ; 不写

#### 


---

> 作者: [晨星_茯苓](/about/)  
> URL: https://poriams.github.io/%E6%84%BF%E5%A4%A9%E5%A0%82%E6%B2%A1%E6%9C%89java%E4%B9%8B%E5%B8%B8%E8%A7%81api/  

