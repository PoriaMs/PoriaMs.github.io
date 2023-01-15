# 愿天堂没有Java之线程


**JavaSE 笔记（八）**

<!--more-->

> Java 是一门非常严谨的语言

#### 线程概述

##### 认识一下嘛

- Java 是通过 java.lang.Thread 类来代表线程的
- 线程是程序内部的一条执行路径
- mian 方法的执行其实就是一条单独的执行路径，这种程序也叫做单线程程序

##### 多线程

- 是指从软硬件上实现多条执行流程的技术
- 消息通信、淘宝、京东系统都离不开多线程技术

#### 多线程的创建

##### 继承 Thread 类

1. 定义一个子类 MyThread 继承 Thread 类，重写 run() 方法
2. 创建 MyThread 类的对象
3. 调用线程对象的 start() 方法启动线程（启动之后还是执行 run() 方法）

```java
class MyThread extends Thread{
  @Override
  public void run(){
    // 定义线程要做的事情
  }
}

public class ThreadDemo{
  public static void main(String[] args){
    Thread t = new MyThread();
    t.start();
  }
}
```

- 只有调用 start 方法才是启动一个新的线程执行，如果直接调用 run 就会被当成普通方法执行
- 该方式编码简单，但是线程类已经继承 Thread，无法继承其他类，不利于扩展

##### 实现 Runnable 接口

1. 定义一个子类 MyThread 实现 Runnable 接口，重写 run() 方法
2. 创建 MyRunnable 任务对象
3. 把 MyRunnable 任务对象交给 Thread 处理
4. 调用线程对象的 start() 方法启动线程

| 构造器                                         | 说明                                         |
| ---------------------------------------------- | -------------------------------------------- |
| `public Thread(Runnable target)`               | 封装Runnable对象成为线程对象                 |
| `public Thread(Runnable target, String name )` | 封装Runnable对象成为线程对象，并指定线程名称 |

```java
class MyRunnable implements Runnable{
  @Override
  public void run(){
    // 定义线程要做的事情
  }
}

public class ThreadDemo{
  public static void main(String[] args){
    Runnable target = new MyRunnable();
    Thread t = new Thread(target)
    t.start();
  }
}

// 以上代码可以简化为
new Thread(new Runnable() {
  @Override
  public void run() {
    for (int i = 0; i < 10; i++) {
      System.out.println("子线程2执行输出：" + i);
    }
  }
}).start();
```

- 该方式可以继续继承类和实现接口，扩展性很强；但是线程执行有结果没办法返回

##### 实现 Callable 接口

1. 定义类实现 Callable 接口，重写 call 方法，封装任务
2. 用 FutureTask 把 Callable 对象封装成线程任务对象
3. 把线程任务对象交给 Thread 处理
4. 调用 start 方法启动线程，执行任务
5. 执行完毕之后，通过 FutureTask 的 get 方法去获取任务执行的结果

| 方法名称                             | 说明                                 |
| ------------------------------------ | ------------------------------------ |
| `public FutureTask<>(Callable call)` | 把Callable对象封装成FutureTask对象。 |
| `public V get() throws Exception`    | 获取线程执行call方法返回的结果。     |

```java
class MyCallable implements Callable<String>{
  @Override
  public String call() throws Exception {
    return 结果;
  }
}

public class ThreadDemo{
  public static void main(String[] args){
    Callable<String> call = new MyCallable();
    FutureTask<String> f = new FutureTask<>(call);
    Thread t = new Thread(f);
    t.start();
    System.out.println("结果：" + f.get());
  }
}
```

#### Thread 常用方法

##### API

| 方法名称                               | 说明                                                         |
| -------------------------------------- | ------------------------------------------------------------ |
| `String getName()`                     | 获取当前线程的名称，默认线程名称是Thread-索引                |
| `void setName(String name)`            | 将此线程的名称更改为指定的名称，通过构造器也可以设置线程名称 |
| `public static Thread currentThread()` | 返回对当前正在执行的线程对象的引用                           |
| `public static void sleep(long time)`  | 让当前线程休眠指定的时间后再继续执行，单位为毫秒             |
| `public  void run()`                   | 线程任务方法                                                 |
| `public  void start()`                 | 线程启动方法                                                 |

##### 构造器

| 方法名称                                      | 说明                                         |
| --------------------------------------------- | -------------------------------------------- |
| `public Thread(String name)`                  | 可以为当前线程指定名称                       |
| `public Thread(Runnable target)`              | 封装Runnable对象成为线程对象                 |
| `public Thread(Runnable target, String name)` | 封装Runnable对象成为线程对象，并指定线程名称 |

#### 线程安全

##### 问题

- 多个线程同时操作同一个共享资源时，会出现的业务安全问题
- 例如：两人拥有共同账户10万元，同时来取钱，并且都取走10万元。每个线程要进行的任务为：1、判断余额是否足够 2、吐出10万元 3、更新账户余额。当两个线程同时运行时，有可能出现两个线程都通过第一步，并执行第二步的情况。

##### 原因

- 存在多线程并发
- 同时访问共享资源
- 存在修改共享资源

#### 线程同步

##### 解决线程安全问题

- 让多个线程实现先后依次访问共享资源

##### 核心思想

- 加锁：将共享的资源上锁，每次只有一个线程能进入，访问完毕之后解锁，其他线程才能进来

##### 方法一：同步代码块

- 作用：把出现线程安全问题的核心代码块上锁

- 原理：每次只有一个线程可以进入核心代码，访问完毕之后解锁

- 格式：

  ```java
  synchronized(同步锁对象){
    操作共享资源的代码(核心代码)
  }
  ```

- 理论上锁对象只要对于当前同时执行的线程来说是一个对象即可，但是这样会影响其他无关线程的运行

- 锁对象的规范

  - 使用共享资源作为锁对象
  - 实例方法：this 作为锁对象
  - 静态方法：字节码（类名.class）作为锁对象

##### 方法二：同步方法

- 作用：把出现线程安全问题的核心方法上锁

- 原理：每次只有一个线程可以进入核心方法，访问完毕之后解锁

- 格式：

  ```java
  修饰符 synchronized 返回值类型 方法名称(形参列表){
    操作共享资源的代码
  }
  ```

- 底层原理

  - 同步方法底层可以看作是隐式锁对象，只是锁的范围是整个方法代码
  - 实例方法：this 作为锁对象，但是方法要高度面向对象
  - 静态方法：字节码（类名.class）作为锁对象

##### 方法三：Lock 锁

- Lock 实现更加广泛的锁定操作

- Lock 是接口，不可以实例化，采用他的实现类 ReentrantLock 来构建 Lock 对象

  | 方法名称                 | 说明                   |
  | ------------------------ | ---------------------- |
  | `public ReentrantLock()` | 获得Lock锁的实现类对象 |
  | `void lock()`            | 获得锁                 |
  | `void unlock()`          | 释放锁                 |

#### 线程通信

##### 实现

- 线程间相互发送数据，线程间共享一个资源即可实现线程通信

##### 常见形式

- 通过共享一个数据的方式实现
- 根据共享数据的情况决定自己该怎么做，以及通知其他线程怎么做
- 生产者消费者模型

##### 等待与唤醒

| 方法名称           | 说明                                                         |
| ------------------ | ------------------------------------------------------------ |
| `void wait()`      | 让当前线程等待并释放所占锁，直到另一个线程调用notify()方法或 notifyAll()方法 |
| `void notify()`    | 唤醒正在等待的单个线程                                       |
| `void notifyAll()` | 唤醒正在等待的所有线程                                       |

#### 线程池

##### 认识一下嘛

- 一种可以复用线程池的技术
- 线程池的接口：`ExecutorService`

##### 获得线程池对象

- 方式一：用 ExecutorService 的实现类 ThreadPoolExcutor 自创一个线程池对象

- 方式二：使用 Executors 线程池的工具类调用方法返回不同特点的线程池对象

- ThreadPoolExcutor 参数说明

  ```java
  public ThreadPoolExecutor(
    int corePoolSize,										// 指定线程池的核心线程数量
    int maximumPoolSize,								// 指定线程池的最大线程数量
    long keepAliveTime,									// 指定临时线程最长存活时间
    TimeUnit unit,								       // 指定存活时间的单位
    BlockingQueue<Runnable> workQueue,    // 指定任务队列
    ThreadFactory threadFactory,			    // 指定线程工厂 
    RejectedExecutionHandler handler) 	  // 指定线程忙时的处理方式
  ```

- 拒绝策略

  | 策略                                     | 详解                                                         |
  | ---------------------------------------- | ------------------------------------------------------------ |
  | `ThreadPoolExecutor.AbortPolicy`         | 丢弃任务并抛出RejectedExecutionException异常。**是默认的策略** |
  | `ThreadPoolExecutor.DiscardPolicy`       | 丢弃任务，但是不抛出异常  这是不推荐的做法                   |
  | `ThreadPoolExecutor.DiscardOldestPolicy` | 抛弃队列中等待最久的任务  然后把当前任务加入队列中           |
  | `ThreadPoolExecutor.CallerRunsPolicy`    | 由主线程负责调用任务的run()方法从而绕过线程池直接执行        |

##### 线程池处理 Runnable 任务

- 示例：

  ```java
  ExecutorService pools = new ThreadPoolExecutor(
    3, 
    5, 
    8, 
    TimeUnit.SECONDS, 
    new ArrayBlockingQueue<>(6),
    Executors.defaultThreadFactory(), 
    new ThreadPoolExecutor.AbortPolicy());
  
  Runnable target = new MyRunnable();
  pool.execute(target);
  pool.shutdown();
  ```

##### 线程池处理 Callable 任务

- 示例

  ```java
  ExecutorService pools = new ThreadPoolExecutor(
    3, 
    5, 
    8, 
    TimeUnit.SECONDS, 
    new ArrayBlockingQueue<>(6),
    Executors.defaultThreadFactory(), 
    new ThreadPoolExecutor.AbortPolicy());
  
  Future<String> f1 = pool.submit(new MyCallable(100));
  System.out.println(f1.get());
  ```

##### 工具类实现线程池

| 方法名称                                                     | 说明                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `public  static ExecutorService newCachedThreadPool()`       | 线程数量随着任务增加而增加，如果线程任务执行完毕且空闲了一段时间则会被回收掉。 |
| `public static ExecutorService newFixedThreadPool(int nThreads)` | 创建固定线程数量的线程池，如果某个线程因为执行异常而结束，那么线程池会补充一个新线程替代它。 |
| `public  static ExecutorService newSingleThreadExecutor ()`  | 创建只有一个线程的线程池对象，如果该线程出现异常而结束，那么线程池会补充一个新线程。 |
| `public  static ScheduledExecutorService newScheduledThreadPool(int corePoolSize)` | 创建一个线程池，可以实现在给定的延迟后运行任务，或者定期执行任务。 |



---

> 作者: [晨星_茯苓](/about/)  
> URL: https://poriams.github.io/%E6%84%BF%E5%A4%A9%E5%A0%82%E6%B2%A1%E6%9C%89java%E4%B9%8B%E7%BA%BF%E7%A8%8B/  

