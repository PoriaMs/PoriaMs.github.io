# 愿天堂没有Java之框架技术


**JavaSE 笔记（九）**

<!--more-->

> Java 是一门非常严谨的语言

#### 反射

##### 认识一下嘛

- 反射是指对于任何一个Class类，在**运行的时候**都可以直接得到这个类全部成分
- 全部成分指构造器对象`Constructor`，成员变量对象`Field`，成员方法对象`Method`
- 这种运行时动态获取类信息以及动态调用类中成分的能力称为Java语言的反射机制

##### 关键

- 反射的第一步都是得到编译后的 Class 类对象，然后就可以得到 Class 的全部成分

  ```java
  HelloWorld.java -> javac -> HelloWorld.class
  
  Class c = HelloWorld.class;
  ```

##### 获取类对象

- 方法一：Class类中的一个静态方法：forName(全限名：包名 + 类名)

  ```java
  Class c = Class.forName("poria.Test");
  ```

- 方法二：类名.class

  ```java
  Class c = Test.class;
  ```

- 方式三：对象.getClass() 获取对象对应类的Class对象

  ```java
  Test t = new Test();
  Class c = t.getClass();
  ```

##### 获取构造器对象

- Class 类用于获取构造器的方法

  | 方法                                                         | 说明                                       |
  | ------------------------------------------------------------ | ------------------------------------------ |
  | `Constructor<?>[] getConstructors()`                         | 返回所有构造器对象的数组（只能拿public的） |
  | `Constructor<?>[] getDeclaredConstructors()`                 | 返回所有构造器对象的数组，存在就能拿到     |
  | `Constructor<T> getConstructor(Class<?>...  parameterTypes)` | 返回单个构造器对象（只能拿public的）       |
  | `Constructor<T> getDeclaredConstructor(Class<?>...  parameterTypes)` | 返回单个构造器对象，存在就能拿到           |

- Constructor 类用于创建对象的方法

  | 符号                                       | 说明                                      |
  | ------------------------------------------ | ----------------------------------------- |
  | `T newInstance(Object...  initargs)`       | 根据指定的构造器创建对象                  |
  | `public void setAccessible(boolean  flag)` | 设置为true,表示取消访问检查，进行暴力反射 |

##### 获取成员变量对象

- Class 类用于获取成员变量的方法

  | 方法                                   | 说明                                         |
  | -------------------------------------- | -------------------------------------------- |
  | `Field[] getFields()`                  | 返回所有成员变量对象的数组（只能拿public的） |
  | `Field[] getDeclaredFields()`          | 返回所有成员变量对象的数组，存在就能拿到     |
  | `Field getField(String  name)`         | 返回单个成员变量对象（只能拿public的）       |
  | `Field getDeclaredField(String  name)` | 返回单个成员变量对象，存在就能拿到           |

- Field 类中用于取值、赋值的方法

  | 方法                                 | 说明   |
  | ------------------------------------ | ------ |
  | `void set(Object obj, Object value)` | 赋值   |
  | `Object get(Object obj)`             | 获取值 |

##### 获取方法对象

- Class 类中用于获取成员方法的方法

  | 方法                                                         | 说明                                         |
  | ------------------------------------------------------------ | -------------------------------------------- |
  | `Method[] getMethods()`                                      | 返回所有成员方法对象的数组（只能拿public的） |
  | `Method[] getDeclaredMethods()`                              | 返回所有成员方法对象的数组，存在就能拿到     |
  | `Method getMethod(String  name, Class<?>... parameterTypes)` | 返回单个成员方法对象（只能拿public的）       |
  | `Method getDeclaredMethod(String  name, Class<?>... parameterTypes)` | 返回单个成员方法对象，存在就能拿到           |

- Method 类中用于触发执行的方法

  | 符号                                        | 说明                                                         |
  | ------------------------------------------- | ------------------------------------------------------------ |
  | `Object invoke(Object obj, Object... args)` | 运行方法  参数一：用obj对象调用该方法  参数二：调用方法的传递的参数（如果没有就不写）  返回值：方法的返回值（如果没有就不写） |

##### 作用

- 在运行时获得一个类的全部成分
- 破坏封装性
- 破坏泛型的约束性
- 做高级框架底层技术

#### 注解

##### 认识一下嘛

- Java 语言中的类、构造器、方法、成员变量、参数等都可以被注解进行标注
- 对 Java 中类、方法、成员变量做标记，然后进行特殊处理

##### 自定义注解

- 格式

  ```java
  public @interface 注解名称 {
    public 属性类型 属性名() default 默认值 ;
  }
  ```

- value 属性，如果只有一个 value 属性的情况下，使用 value 属性的时候可以省略 value 名称不写

##### 元注解

- 就是用来注解注解的注解（绕口令

- 元注解有两个

  - @Target：约束自定义注解只能在哪些地方使用
  - 常用值
    - TYPE，类，接口
    - FIELD，成员变量
    - METHOD，成员方法
    - PARAMETER, 方法参数
    - CONSTRUCTOR, 构造器
    - LOCAL_VARIABLE, 局部变量
  - @Retention：申明注解的生命周期
  - 常用值
    - SOURCE： 注解只作用在源码阶段，生成的字节码文件中不存在
    - CLASS： 注解作用在源码阶段，字节码文件阶段，运行阶段不存在，默认值.
    - RUNTIME：注解作用在源码阶段，字节码文件阶段，运行阶段（开发常用）

- 用例

  ```java
  @Target({ElementType.METHOD,ElementType.FIELD}) // 元注解
  @Retention(RetentionPolicy.RUNTIME) // 一直活着，在运行阶段这个注解也不消失
  public @interface MyTest {
  }
  ```

##### 注解解析

- 注解的操作中经常需要进行解析，注解的解析就是判断是否存在注解，存在注解就解析出内容

- 注解相关接口

  - Annotation：注解的顶级接口，注解都是 Annotation 类型的对象
  - AnnotatedElement：该接口定义了与注解解析相关的解析方法

- 常用方法

  | 方法                                                         | 说明                                                         |
  | ------------------------------------------------------------ | ------------------------------------------------------------ |
  | `Annotation[] getDeclaredAnnotations()`                      | 获得当前对象上使用的所有注解，返回注解数组。                 |
  | `T getDeclaredAnnotation(Class<T>  annotationClass)`         | 根据注解类型获得对应注解对象                                 |
  | `boolean isAnnotationPresent(Class<Annotation>  annotationClass)` | 判断当前对象是否使用了指定的注解，如果使用了则返回true，否则false |

- 所有的类成分Class，Method，Field，Constructor，都实现了 AnnotatedElement 接口他们都拥有解析注解的能力

- 技巧

  - 注解在哪个成分上，我们就先拿哪个成分对象。
  - 比如注解作用成员方法，则要获得该成员方法对应的 Method 对象，再来拿上面的注解
  - 比如注解作用在类上，则要该类的 Class 对象，再来拿上面的注解
  - 比如注解作用在成员变量上，则要获得该成员变量对应的 Field 对象，再来拿上面的注解

##### 单元测试

- 单元测试就是针对最小的功能单元编写测试代码，Java 程序最小的功能单元是方法，因此，单元测试就是针对 Java 方法的测试，进而检查方法的正确性

- 测试方法使用 @Test 注解标记

- 定义的测试方法必须是无参数无返回值，且公开的方法

  | 注解          | 说明                                                         |
  | ------------- | ------------------------------------------------------------ |
  | `@Test`       | 测试方法                                                     |
  | `@BeforeEach` | 用来修饰实例方法，该方法会在每一个测试方法执行之前执行一次。 |
  | `@AfterEach`  | 用来修饰实例方法，该方法会在每一个测试方法执行之后执行一次。 |
  | `@BeforeAll`  | 用来静态修饰方法，该方法会在所有测试方法之前只执行一次。     |
  | `@AfterAll`   | 用来静态修饰方法，该方法会在所有测试方法之后只执行一次。     |

#### 动态代理

##### 认识一下嘛

- 代理就是被代理者没有能力或者不愿意去完成某件事情，需要找个人代替自己去完成这件事，动态代理就是用来对业务功能（方法）进行代理的

##### 关键步骤

- 必须有接口，实现类要实现接口
- 创建一个实现类的对象，该对象为业务对象，然后为业务对象创建一个代理对象

##### 用例

```java
    public static <T> T  getProxy(T obj) {
        // 返回了一个代理对象了
        return (T)Proxy.newProxyInstance(obj.getClass().getClassLoader(), obj.getClass().getInterfaces(),
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        // 参数一：代理对象本身
                        // 参数二：正在被代理的方法
                        // 参数三：被代理方法，应该传入的参数
                       long startTimer = System .currentTimeMillis();
                        // 马上触发方法的真正执行。(触发真正的业务功能)
                        Object result = method.invoke(obj, args);

                        long endTimer = System.currentTimeMillis();
                        System.out.println(method.getName() + "方法耗时：" + (endTimer - startTimer) / 1000.0 + "s");

                        // 把业务功能方法执行的结果返回给调用者
                        return result;
                    }
                });
    }
```

##### 优点

- 非常的灵活，支持任意接口类型的实现类对象做代理，也可以直接为接本身做代理
- 可以为被代理对象的所有方法做代理
- 可以在不改变方法源码的情况下，实现对方法功能的增强
- 不仅简化了编程工作、提高了软件系统的可扩展性，同时也提高了开发效率


---

> 作者: [晨星_茯苓](/about/)  
> URL: https://poriams.github.io/%E6%84%BF%E5%A4%A9%E5%A0%82%E6%B2%A1%E6%9C%89java%E4%B9%8B%E6%A1%86%E6%9E%B6%E6%8A%80%E6%9C%AF/  

