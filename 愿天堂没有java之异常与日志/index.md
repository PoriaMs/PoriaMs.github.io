# 愿天堂没有Java之异常与日志


**JavaSE 笔记（六）**

<!--more-->

> Java 是一门非常严谨的语言

#### 异常概述

##### 认识一下嘛

- 异常是程序在“编译”或“执行”过程中可能出现的问题
- 比如：数组索引越界，空指针异常，日期格式化异常，等
- 异常一旦出现，如果不处理，程序就会退出 JVM 虚拟机而终止
- 研究异常并且避免异常，然后提前处理异常，体现的是程序的安全，健壮性

##### 体系

- Error：系统级别的问题，JVM 退出等，代码无法控制
- Exception：java.lang 包下，称为异常类，它表示程序本身可以处理的问题
  - RuntimeException 及其子类：运行时异常，编译阶段不会报错（空指针异常，数组越界异常）
  - 除了上面那个异常之外的所有异常：编译时报错，编译期必须处理（日期格式化异常）

##### 两种异常的说明

- 编译时异常，是在编译成 class 文件时必须要处理的异常，也称之为受检异常
- 运行时异常，在编译成 class 文件时不需要处理，在运行字节码文件时可能出现的异常

#### 默认处理流程

##### 流程

1. 默认会在出现异常的代码那里自动的创建一个异常对象
2. 异常会从方法中出现的点这里抛出给调用者，调用者最终抛出给 JVM 虚拟机
3. 虚拟机接到异常对象后，先在控制台直接输出异常栈信息
4. 直接从当前执行的异常点结束掉当前程序
5. 后续代码没有机会执行，因为程序已经死亡

##### 机制

- 默认机制并不好，一旦程序出现异常，就立即死亡

#### 异常处理机制

##### 编译时异常

- 方式一：throws

  - 用在方法上，可以将方法内部出现的异常抛出去给本方法的调用者处理

  - 这种方式并不好，发生异常的方法自己不去处理异常，如果异常最终抛给虚拟机将引起程序死亡

    格式

    ```java
    方法 throws 异常1，异常2，异常3 ...{
    }
    
    // 推荐做法
    方法 throws Exception{
      // 代表可以抛出一切异常
    }
    ```

- 方法二：try...catch...

  - 监视捕获异常，用在方法内部，可以将方法内部出现的异常直接捕获

  - 这种方式较为常用，发生异常的方法自己独立完成异常的处理，程序可以继续往下执行

    ```java
    try{
      // 监视可能出现异常的代码
    }catch(异常类型1 变量){
      // 处理异常
    }catch(异常类型2 变量){
      // 处理异常
    }
    
    try{
      // 可能出现异常的代码
    }catch(Exception e){
      e.printStackTrace();	// 直接打印异常栈信息
    }
    ```

- 方式三：前两者结合

  - 方法直接抛出异常给调用者

  - 调用者收到异常后捕获处理

    ```java
    public static void main(String[] args) {
      try {
        parseTime("2011-11-11 11:11:11");
        System.out.println("功能操作成功~~~");
      } catch (Exception e) {
        e.printStackTrace();
        System.out.println("功能操作失败~~~");
      }
    }
    public static void parseTime(String date) throws Exception {
      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      Date d = sdf.parse(date);
      System.out.println(d);
      InputStream is = new FileInputStream("D:/Poria.jpg");
    }
    ```

- 运行时异常的处理机制，建议使用方式三来处理

#### 自定义异常

##### 必要性

- Java 无法为这个世界上全部的问题提供异常类
- 如果想通过异常的方式来管理自己的某个业务，就需要自定义异常类

##### 分类

- 自定义编译时异常
  - 定义一个异常类继承 Exception
  - 重写构造器
  - 在出现异常的地方用 throw new 自定义对象抛出
- 自定义运行时异常
  - 定义一个异常类继承 RuntimeException
  - 重写构造器
  - 在出现异常的地方用 throw new 自定义对象抛出

#### 日志技术概述

##### 认识一下嘛

- 用来记录程序运行过程中的信息，并且进行永久存储

##### 优势

- 可以将系统执行的信息选择性的记录到指定的位置（控制台、文件中、数据库）
- 可以随时以开关的形式控制是否记录日志，无需修改源代码
- 多线程性能较好

#### 体系

##### 日志规范

- 一些接口，提供给日志的实现框架设计的标准
- 常见规范有
  - Commons Logging 简称：`JCL`
  - Simple Logging Facade For Java 简称：`slf4j`

##### 日志框架

- Log4j
- JUL（java.util.logging）
- Logback

#### Logback

##### 认识一下嘛

- 官网：https://logback.qos.ch/index.html
- Logback 是由 log4j 创始人设计的另一个开源日志组件，性能较好
- 基于 slf4j 实现

##### 三个模块

- logback-core：为其他两个模块奠定了基础
- logback-classic：是 log4j 的一个改良版本，同时完整实现了 slf4j API
- logback-access：与 Tomcat 和 Jetty 等 Serlvet 容器集成，以提供 HTTP 访问日志功能

#####  使用步骤

- 在项目下新建 lib 文件夹，导入 Logback 的相关 jar 包到该文件夹下，并添加到项目库中
- 必须将 Logback 的核心配置文件 logback.xml 直接拷贝到 src 目录下
- 在代码中获取日志的对象 ：`public static final Logger LOGGER = LoggerFactory.getLogger("类对象");`
- 使用日志对象输出日志信息

##### 配置文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    
  <!-- CONSOLE：表示当前的日志信息是可以输出到控制台的 -->
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <!-- 输出流对象 默认 System.out 改为 System.err -->
        <target>System.out</target>
        <encoder>
            <!-- 格式化输出：%d表示日期，%thread表示线程名，%-5level：级别从左显示5个字符宽度，%msg：日志消息，%n是换行符 -->
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%-5level]  %c [%thread] : %msg%n</pattern>
        </encoder>
    </appender>

    <!-- File是输出的方向通向文件的 -->
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
            <charset>utf-8</charset>
        </encoder>
        <!--日志输出路径-->
        <file>/var/log/poria</file>
        <!--指定日志文件拆分和压缩规则-->
        <rollingPolicy
                class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <!--通过指定压缩文件名称，来确定分割文件方式-->
            <fileNamePattern>C:/code/itheima-data2-%d{yyyy-MM-dd}.log%i.gz</fileNamePattern>
            <!--文件拆分大小-->
            <maxFileSize>1MB</maxFileSize>
        </rollingPolicy>
    </appender>

    <!--
    level:用来设置打印级别，大小写无关：TRACE, DEBUG, INFO, WARN, ERROR, ALL 和 OFF 默认debug
    <root>可以包含零个或多个<appender-ref>元素，标识这个输出位置将会被本日志级别控制
    -->
    <root level="ALL">
        <!-- 注意：如果这里不配置关联打印位置，该位置将不会记录日志-->
        <appender-ref ref="FILE" />
    </root>
</configuration>
```


---

> 作者: [晨星_茯苓](/about/)  
> URL: https://poriams.github.io/%E6%84%BF%E5%A4%A9%E5%A0%82%E6%B2%A1%E6%9C%89java%E4%B9%8B%E5%BC%82%E5%B8%B8%E4%B8%8E%E6%97%A5%E5%BF%97/  

