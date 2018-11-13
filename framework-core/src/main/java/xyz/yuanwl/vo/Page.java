package xyz.yuanwl.vo;

import lombok.Data;

import java.util.List;

/**
 * 分页对象，既可以用来作为分页参数，也可以作为分页结果。
 * <p>
 * 创建人：袁炜林 <br>
 * 创建时间：2017年10月19日 上午3:37:35 <br>
 * <p>
 * 修改人： <br>
 * 修改时间： <br>
 * 修改备注： <br>
 * </p>
 */
@Data
public class Page<T> {
	
	/**
	 * 页码
	 */
	private int pageNo;
	
	/**
	 * 每页行数
	 */
	private int pageSize;

    /**
     * 以哪个属性排序
     */
    private String orderBy;

	/**
	 * asc（升序） 还是 desc（降序）
	 */
    private String direct;
    
	/**
	 * （暂时不使用）查找条件拼接，如 "name=LIKE %龙';age=>20"
	 */
	private String condition;
	
	/**
	 * 总页数
	 */
	private int totalPages;
	
	/**
	 * 总行数
	 */
	private int totalRows;

	/**
	 * 数据集合
	 */
	List<T> data;
	
}
