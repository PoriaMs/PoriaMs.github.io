# 愿天堂没有Java之Stream流


**JavaSE 笔记（五）**

<!--more-->

> Java 是一门非常严谨的语言

#### Stream 流概述

##### 认识一下嘛

- 得益于 Lambda 所带来的函数式编程，出现了 Stream 流的概念
- 用于简化集合和数组操作的 API

##### 思想

- 先得到集合或者数组的 Stream 流
- 将元素放在上面
- 用 Stream 流简化的方式来方便的操作元素

##### 流的三类方法

- 获取流：创建一条流水线，并把数据放在流水线上操作
- 中间方法：一次操作完成之后，还可以继续其他操作
- 终结方法：一个流只能有一个终结方法，是流水线上的最后一个操作

#### 流的获取

##### 集合获取流

- 使用 Collection 接口中的默认方法

  | 名称                          | 说明                       |
  | ----------------------------- | -------------------------- |
  | `default  Stream<E> stream()` | 获取当前集合对象的Stream流 |

- 用例

  ```java
  // Collection集合获取流
  Collection<String> list = new ArrayList<>();
  Stream<String> s =  list.stream();
  
  // Map集合获取流
  Map<String, Integer> maps = new HashMap<>();							
  Stream<String> keyStream = maps.keySet().stream();	// 键流		    
  Stream<Integer> valueStream = maps.values().stream();	// 值流			
  Stream<Map.Entry<String,Integer>> keyAndValueStream =  maps.entrySet().stream();	// 键值对流（拿整体）
  ```

##### 数组获取流

- 用到的方法

  | 名称                                                | 说明                            |
  | --------------------------------------------------- | ------------------------------- |
  | `public  static <T>  Stream<T>  stream(T[]  array)` | 获取当前数组的Stream流          |
  | `public  static<T>  Stream<T>  of(T...  values)`    | 获取当前数组/可变数据的Stream流 |

- 用例

  ```java
  String[] names = {"Poria","Pupi1"};
  Stream<String> nameStream1 = Arrays.stream(names);
  Stream<String> nameStream2 = Stream.of(names);
  ```

#### 流的中间方法

##### 常用方法

| 名称                                                   | 说明                                           |
| ------------------------------------------------------ | ---------------------------------------------- |
| `Stream<T>  filter(Predicate<?  super  T>  predicate)` | 用于对流中的数据进行**过滤。**                 |
| `Stream<T>  limit(long maxSize)`                       | 获取前几个元素                                 |
| `Stream<T>  skip(long n)`                              | 跳过前几个元素                                 |
| `Stream<T>  distinct()`                                | 去除流中重复的元素。依赖(hashCode和equals方法) |
| `static  <T> Stream<T> concat(Stream  a, Stream b)`    | **合并**a和b两个流为一个流                     |

##### 注意事项

- 中间方法也称非终结方法，调用完成之后返回新的流可以继续使用，支持链式编程
- 在流中无法直接修改集合、数组中的数据

#### 流的终结方法

##### 常用方法

| 名称                              | 说明                         |
| --------------------------------- | ---------------------------- |
| `void  forEach(Consumer  action)` | 对此流的每个元素执行遍历操作 |
| `long count()`                    | 返回此流中的元素数           |

##### 注意事项

- 调用之后无法继续使用流了，因为这些方法不会返回流

#### 流的收集

##### 认识一下嘛

- 把流操作后的结果数据转回到集合或者数组中去
- 流只是方便操作集合/数组的**手段**，集合/数组才是开发中的**目的**

##### 收集方法

| 名称                             | 说明                         |
| -------------------------------- | ---------------------------- |
| `R collect(Collector collector)` | 开始收集Stream流，指定收集器 |

Collectors 工具类中提供了具体的收集方法

| 名称                                                         | 说明                   |
| ------------------------------------------------------------ | ---------------------- |
| `public static <T> Collector toList()`                       | 把元素收集到List集合中 |
| `public static <T> Collector toSet()`                        | 把元素收集到Set集合中  |
| `public static Collector toMap(Function keyMapper  , Function valueMapper)` | 把元素收集到Map集合中  |


---

> 作者: [晨星_茯苓](/about/)  
> URL: https://poriams.github.io/%E6%84%BF%E5%A4%A9%E5%A0%82%E6%B2%A1%E6%9C%89java%E4%B9%8Bstream%E6%B5%81/  

