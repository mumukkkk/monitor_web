#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
趋势预测算法模块
提供基于历史数据的趋势预测分析功能
"""

import numpy as np
from datetime import datetime, timedelta
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('prediction_utils')


class PredictionModel:
    """趋势预测模型类"""
    
    def __init__(self):
        self.models = {
            'moving_average': self._moving_average,
            'linear_regression': self._linear_regression,
            'exponential_smoothing': self._exponential_smoothing
        }
    
    def predict(self, data, prediction_days=7, algorithm='linear_regression', metric_type='cpu'):
        """
        执行预测
        
        Args:
            data: 历史数据列表，每个元素包含(check_time, value)
            prediction_days: 预测未来的天数
            algorithm: 预测算法，可选 'moving_average', 'linear_regression', 'exponential_smoothing'
            metric_type: 指标类型，用于调整预测参数
            
        Returns:
            预测结果列表，每个元素包含(predicted_time, predicted_value)
        """
        try:
            # 验证数据
            if not data or len(data) < 3:
                logger.warning(f"数据量不足，无法进行预测: {len(data)}条记录")
                return []
            
            # 选择算法
            if algorithm not in self.models:
                logger.error(f"未知的预测算法: {algorithm}")
                algorithm = 'linear_regression'  # 默认使用线性回归
            
            # 提取数值和时间
            times = [item[0] for item in data]
            values = [item[1] for item in data]
            
            # 执行预测
            predictions = self.models[algorithm](values, prediction_days, metric_type)
            
            # 生成预测时间点
            last_time = datetime.strptime(times[-1], '%Y-%m-%d %H:%M:%S')
            prediction_times = []
            
            # 根据数据密度确定预测时间间隔
            if len(times) > 1:
                first_time = datetime.strptime(times[0], '%Y-%m-%d %H:%M:%S')
                avg_interval = (last_time - first_time).total_seconds() / (len(times) - 1)
                
                # 确定预测点数量，按天预测
                points_per_day = max(1, int(86400 / avg_interval))
                total_points = min(prediction_days * points_per_day, 100)  # 最多预测100个点
                
                for i in range(1, total_points + 1):
                    pred_time = last_time + timedelta(seconds=avg_interval * i)
                    prediction_times.append(pred_time.strftime('%Y-%m-%d %H:%M:%S'))
            else:
                # 如果只有一个数据点，按小时预测
                for i in range(1, prediction_days * 24 + 1):
                    pred_time = last_time + timedelta(hours=i)
                    prediction_times.append(pred_time.strftime('%Y-%m-%d %H:%M:%S'))
            
            # 确保预测值在合理范围内（0-100%）
            validated_predictions = []
            for i, pred in enumerate(predictions[:len(prediction_times)]):
                if metric_type in ['cpu', 'memory', 'disk']:
                    # 资源使用率限制在0-100%之间
                    validated_pred = max(0, min(100, pred))
                else:
                    # 网络流量允许为正值
                    validated_pred = max(0, pred)
                validated_predictions.append((prediction_times[i], validated_pred))
            
            return validated_predictions
            
        except Exception as e:
            logger.error(f"预测过程中发生错误: {str(e)}")
            return []
    
    def _moving_average(self, values, prediction_days, metric_type):
        """移动平均预测法"""
        # 根据数据量动态调整窗口大小
        window_size = min(7, max(3, len(values) // 5))
        
        # 计算移动平均
        moving_averages = []
        for i in range(len(values) - window_size + 1):
            window_avg = sum(values[i:i+window_size]) / window_size
            moving_averages.append(window_avg)
        
        # 预测未来值（简单假设最近的移动平均值作为趋势）
        if not moving_averages:
            return [values[-1]] * prediction_days
        
        # 计算趋势斜率
        if len(moving_averages) > 1:
            slope = (moving_averages[-1] - moving_averages[0]) / (len(moving_averages) - 1)
        else:
            slope = 0
        
        # 生成预测
        predictions = []
        last_value = moving_averages[-1]
        
        # 按预测时间点数量生成预测值
        prediction_points = min(prediction_days * 24, 100)  # 最多100个预测点
        for i in range(prediction_points):
            # 添加一些随机性以模拟现实波动
            noise = np.random.normal(0, max(0.1, np.std(values) * 0.2)) if len(values) > 1 else 0
            pred = last_value + slope * i + noise
            predictions.append(pred)
        
        return predictions
    
    def _linear_regression(self, values, prediction_days, metric_type):
        """线性回归预测法"""
        # 创建x坐标（时间索引）
        x = np.array(range(len(values)))
        y = np.array(values)
        
        # 计算线性回归参数
        if len(values) > 1:
            n = len(x)
            sum_x = np.sum(x)
            sum_y = np.sum(y)
            sum_xy = np.sum(x * y)
            sum_x2 = np.sum(x * x)
            
            # 计算斜率和截距
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
            intercept = (sum_y - slope * sum_x) / n
        else:
            slope = 0
            intercept = values[0]
        
        # 生成预测
        predictions = []
        last_index = len(values)
        
        # 按预测时间点数量生成预测值
        prediction_points = min(prediction_days * 24, 100)  # 最多100个预测点
        
        # 计算历史数据的标准差作为噪声基础
        std_dev = np.std(values) if len(values) > 1 else 0.1
        
        for i in range(prediction_points):
            # 基本线性预测
            base_pred = slope * (last_index + i) + intercept
            
            # 添加噪声，噪声强度根据指标类型调整
            if metric_type in ['cpu', 'memory']:
                # CPU和内存波动较大
                noise = np.random.normal(0, std_dev * 0.3)
            elif metric_type == 'disk':
                # 磁盘使用较稳定
                noise = np.random.normal(0, std_dev * 0.1)
            else:
                # 网络流量波动大
                noise = np.random.normal(0, std_dev * 0.5)
            
            predictions.append(base_pred + noise)
        
        return predictions
    
    def _exponential_smoothing(self, values, prediction_days, metric_type):
        """指数平滑预测法"""
        # 根据指标类型选择平滑因子
        if metric_type == 'disk':
            # 磁盘使用变化缓慢，使用较小的平滑因子
            alpha = 0.2
        elif metric_type in ['cpu', 'memory']:
            # CPU和内存使用中等波动
            alpha = 0.3
        else:
            # 网络流量变化较快，使用较大的平滑因子
            alpha = 0.4
        
        # 初始化平滑值
        smoothed = [values[0]]
        
        # 计算指数平滑值
        for i in range(1, len(values)):
            smoothed_val = alpha * values[i] + (1 - alpha) * smoothed[i-1]
            smoothed.append(smoothed_val)
        
        # 生成预测
        predictions = []
        last_smoothed = smoothed[-1]
        
        # 计算趋势
        if len(smoothed) > 1:
            # 简单计算最近的趋势
            recent_trend = (smoothed[-1] - smoothed[-2])
        else:
            recent_trend = 0
        
        # 按预测时间点数量生成预测值
        prediction_points = min(prediction_days * 24, 100)  # 最多100个预测点
        
        # 计算历史数据的标准差作为噪声基础
        std_dev = np.std(values) if len(values) > 1 else 0.1
        
        for i in range(prediction_points):
            # 基础预测值 = 最后平滑值 + 趋势 * 预测步数
            base_pred = last_smoothed + recent_trend * (i + 1)
            
            # 添加噪声，随预测步数增加而增大
            noise_scale = 1 + i * 0.01  # 预测越远，不确定性越大
            noise = np.random.normal(0, std_dev * 0.2 * noise_scale)
            
            predictions.append(base_pred + noise)
        
        return predictions
    
    def evaluate_prediction_quality(self, actual_data, predicted_data):
        """
        评估预测质量
        
        Args:
            actual_data: 实际数据
            predicted_data: 预测数据
            
        Returns:
            包含评估指标的字典
        """
        if len(actual_data) != len(predicted_data):
            logger.warning(f"实际数据和预测数据长度不匹配: {len(actual_data)} vs {len(predicted_data)}")
            # 取较短的长度进行评估
            min_length = min(len(actual_data), len(predicted_data))
            actual_data = actual_data[:min_length]
            predicted_data = predicted_data[:min_length]
        
        try:
            actual_values = np.array([item[1] for item in actual_data])
            predicted_values = np.array([item[1] for item in predicted_data])
            
            # 计算均方误差 (MSE)
            mse = np.mean((actual_values - predicted_values) ** 2)
            
            # 计算平均绝对误差 (MAE)
            mae = np.mean(np.abs(actual_values - predicted_values))
            
            # 计算均方根误差 (RMSE)
            rmse = np.sqrt(mse)
            
            # 计算平均绝对百分比误差 (MAPE)
            non_zero_actual = actual_values[actual_values != 0]
            non_zero_predicted = predicted_values[actual_values != 0]
            
            if len(non_zero_actual) > 0:
                mape = np.mean(np.abs((non_zero_actual - non_zero_predicted) / non_zero_actual)) * 100
            else:
                mape = float('inf')
            
            # 计算R平方值
            if len(actual_values) > 1:
                ss_res = np.sum((actual_values - predicted_values) ** 2)
                ss_tot = np.sum((actual_values - np.mean(actual_values)) ** 2)
                r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
            else:
                r_squared = 0
            
            return {
                'mse': mse,
                'mae': mae,
                'rmse': rmse,
                'mape': mape,
                'r_squared': r_squared
            }
        except Exception as e:
            logger.error(f"评估预测质量时发生错误: {str(e)}")
            return {
                'mse': float('inf'),
                'mae': float('inf'),
                'rmse': float('inf'),
                'mape': float('inf'),
                'r_squared': 0
            }


def predict_resource_trend(host_ip, metric_type, prediction_days=7, algorithm='linear_regression'):
    """
    预测指定主机和指标的趋势
    
    Args:
        host_ip: 主机IP地址
        metric_type: 指标类型 (cpu, memory, disk, network_rx, network_tx)
        prediction_days: 预测天数
        algorithm: 预测算法
        
    Returns:
        预测结果和评估指标
    """
    from .database_utils import DatabaseUtils
    
    try:
        # 获取数据库连接
        db = DatabaseUtils()
        
        # 获取历史数据
        # 为了有足够的历史数据用于预测，我们获取最近30天的数据
        end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        start_time = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
        
        # 选择合适的指标字段
        metric_field_map = {
            'cpu': 'cpu_usage',
            'memory': 'memory_usage',
            'disk': 'disk_usage',
            'network_rx': 'network_rx',
            'network_tx': 'network_tx'
        }
        
        if metric_type not in metric_field_map:
            logger.error(f"不支持的指标类型: {metric_type}")
            return {
                'success': False,
                'message': f'不支持的指标类型: {metric_type}',
                'predictions': []
            }
        
        metric_field = metric_field_map[metric_type]
        
        # 查询历史数据
        historical_data = db.get_historical_data_by_metric(
            host_ip=host_ip,
            metric_field=metric_field,
            start_time=start_time,
            end_time=end_time
        )
        
        # 转换数据格式
        data_for_prediction = []
        for row in historical_data:
            # 假设返回的行格式为 (check_time, metric_value)
            if len(row) >= 2 and row[1] is not None:
                data_for_prediction.append((row[0], float(row[1])))
        
        if not data_for_prediction:
            logger.warning(f"未找到主机 {host_ip} 的 {metric_type} 历史数据")
            return {
                'success': False,
                'message': f'未找到足够的历史数据用于预测',
                'predictions': []
            }
        
        # 初始化预测模型并执行预测
        model = PredictionModel()
        predictions = model.predict(
            data=data_for_prediction,
            prediction_days=prediction_days,
            algorithm=algorithm,
            metric_type=metric_type if metric_type in ['cpu', 'memory', 'disk'] else 'network'
        )
        
        # 为了评估预测质量，我们使用一部分历史数据进行回测
        evaluation_metrics = None
        if len(data_for_prediction) >= 10:  # 至少需要10个数据点进行评估
            # 使用80%的数据进行训练，20%进行测试
            train_size = int(len(data_for_prediction) * 0.8)
            train_data = data_for_prediction[:train_size]
            test_data = data_for_prediction[train_size:]
            
            # 使用训练数据预测测试数据的时间段
            test_predictions = model.predict(
                data=train_data,
                prediction_days=len(test_data) / 24,  # 估算天数
                algorithm=algorithm,
                metric_type=metric_type if metric_type in ['cpu', 'memory', 'disk'] else 'network'
            )
            
            # 评估预测质量
            if len(test_predictions) >= len(test_data):
                evaluation_metrics = model.evaluate_prediction_quality(test_data, test_predictions[:len(test_data)])
        
        return {
            'success': True,
            'message': '预测成功',
            'predictions': predictions,
            'historical_data': data_for_prediction,
            'evaluation_metrics': evaluation_metrics,
            'algorithm': algorithm,
            'prediction_days': prediction_days
        }
        
    except Exception as e:
        logger.error(f"预测资源趋势时发生错误: {str(e)}")
        return {
            'success': False,
            'message': f'预测过程中发生错误: {str(e)}',
            'predictions': []
        }


def generate_capacity_recommendation(predictions, metric_type, current_capacity=None):
    """
    根据预测结果生成容量规划建议
    
    Args:
        predictions: 预测结果列表
        metric_type: 指标类型
        current_capacity: 当前容量值（如果知道）
        
    Returns:
        容量规划建议
    """
    try:
        if not predictions:
            return {
                'success': False,
                'message': '没有预测数据，无法生成建议',
                'recommendations': []
            }
        
        # 提取预测值
        predicted_values = [p[1] for p in predictions]
        
        # 计算关键指标
        max_value = max(predicted_values)
        avg_value = sum(predicted_values) / len(predicted_values)
        median_value = np.median(predicted_values)
        
        # 计算增长趋势
        if len(predicted_values) > 1:
            # 简单线性拟合计算趋势
            x = np.arange(len(predicted_values))
            slope = np.polyfit(x, predicted_values, 1)[0]
            trend_per_day = slope * (24 / len(predicted_values))  # 估算每天的增长率
        else:
            trend_per_day = 0
        
        # 确定阈值（根据指标类型）
        threshold_map = {
            'cpu': 80,      # CPU使用率阈值80%
            'memory': 85,   # 内存使用率阈值85%
            'disk': 80,     # 磁盘使用率阈值80%
            'network_rx': float('inf'),  # 网络接收无固定阈值
            'network_tx': float('inf')   # 网络发送无固定阈值
        }
        
        threshold = threshold_map.get(metric_type, 80)
        
        # 生成建议
        recommendations = []
        
        # 容量预警
        if max_value > threshold:
            # 找出超过阈值的时间点
            exceed_points = []
            for time, value in predictions:
                if value > threshold:
                    exceed_points.append((time, value))
            
            if exceed_points:
                first_exceed_time = exceed_points[0][0]
                recommendations.append({
                    'type': 'warning',
                    'title': f'{metric_type.upper()}容量预警',
                    'description': f'预计在 {first_exceed_time} 左右，{metric_type} 使用将超过警戒线({threshold}%)',
                    'severity': 'high',
                    'suggestion': '建议尽快扩容或优化资源使用'
                })
        
        # 增长趋势分析
        if trend_per_day > 0.5:  # 如果每天增长超过0.5%
            doubling_time_days = None
            if trend_per_day > 0 and avg_value > 0:
                # 估算翻倍时间
                doubling_time_days = (100 - avg_value) / (2 * trend_per_day) if trend_per_day > 0 else float('inf')
            
            recommendations.append({
                'type': 'growth',
                'title': f'{metric_type.upper()}增长趋势分析',
                'description': f'{metric_type} 使用呈上升趋势，平均每天增长 {trend_per_day:.2f}%',
                'severity': 'medium',
                'suggestion': f'建议提前规划扩容，预计{"%.0f天内使用量将翻倍" % doubling_time_days if doubling_time_days and doubling_time_days < 365 else "需要持续监控"}'
            })
        
        # 资源利用率建议
        if metric_type in ['cpu', 'memory', 'disk']:
            if avg_value < 30:
                recommendations.append({
                    'type': 'utilization',
                    'title': f'{metric_type.upper()}利用率分析',
                    'description': f'{metric_type} 平均使用率较低({avg_value:.1f}%)',
                    'severity': 'low',
                    'suggestion': '考虑资源整合或降级，优化成本'
                })
            elif avg_value > 70:
                recommendations.append({
                    'type': 'utilization',
                    'title': f'{metric_type.upper()}利用率分析',
                    'description': f'{metric_type} 平均使用率较高({avg_value:.1f}%)',
                    'severity': 'medium',
                    'suggestion': '建议评估是否需要扩容以避免性能问题'
                })
        
        # 如果没有特定建议，提供一般建议
        if not recommendations:
            recommendations.append({
                'type': 'general',
                'title': f'{metric_type.upper()}使用情况正常',
                'description': f'{metric_type} 使用在可接受范围内，最大值{max_value:.1f}%，平均值{avg_value:.1f}%',
                'severity': 'low',
                'suggestion': '建议保持当前配置，继续监控'
            })
        
        return {
            'success': True,
            'message': '容量规划建议生成成功',
            'recommendations': recommendations,
            'statistics': {
                'max_value': max_value,
                'avg_value': avg_value,
                'median_value': median_value,
                'trend_per_day': trend_per_day
            }
        }
        
    except Exception as e:
        logger.error(f"生成容量规划建议时发生错误: {str(e)}")
        return {
            'success': False,
            'message': f'生成建议过程中发生错误: {str(e)}',
            'recommendations': []
        }
