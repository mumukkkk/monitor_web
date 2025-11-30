#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
容量规划建议功能模块
提供基于预测结果的资源配置方案和容量规划建议
"""

import numpy as np
from datetime import datetime, timedelta
import logging
from .prediction_utils import predict_resource_trend, generate_capacity_recommendation

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('capacity_planning_utils')


class CapacityPlanner:
    """容量规划器类"""
    
    # 资源扩展阈值配置
    EXTENSION_THRESHOLDS = {
        'cpu': 80,      # CPU使用率超过80%建议扩展
        'memory': 85,   # 内存使用率超过85%建议扩展
        'disk': 80,     # 磁盘使用率超过80%建议扩展
        'network_rx': 0, # 网络接收无固定阈值，根据具体情况分析
        'network_tx': 0  # 网络发送无固定阈值，根据具体情况分析
    }
    
    # 资源降级阈值配置
    DOWNGRADE_THRESHOLDS = {
        'cpu': 30,      # CPU使用率低于30%建议降级
        'memory': 30,   # 内存使用率低于30%建议降级
        'disk': 40,     # 磁盘使用率低于40%建议降级
        'network_rx': 0,
        'network_tx': 0
    }
    
    # 资源成本估算（单位：元/天）
    RESOURCE_COSTS = {
        'cpu': {
            'small': 10,   # 小型CPU配置
            'medium': 25,  # 中型CPU配置
            'large': 50    # 大型CPU配置
        },
        'memory': {
            'small': 15,   # 小型内存配置
            'medium': 35,  # 中型内存配置
            'large': 70    # 大型内存配置
        },
        'disk': {
            'small': 5,    # 小型磁盘配置
            'medium': 15,  # 中型磁盘配置
            'large': 30    # 大型磁盘配置
        }
    }
    
    def __init__(self):
        pass
    
    def generate_comprehensive_plan(self, host_ip, prediction_days=7):
        """
        生成综合容量规划建议
        
        Args:
            host_ip: 主机IP地址
            prediction_days: 预测天数
            
        Returns:
            综合容量规划建议
        """
        try:
            # 需要分析的所有指标
            metrics = ['cpu', 'memory', 'disk', 'network_rx', 'network_tx']
            
            # 获取所有指标的预测结果
            predictions = {}
            recommendations = {}
            
            for metric in metrics:
                # 获取预测结果
                pred_result = predict_resource_trend(
                    host_ip=host_ip,
                    metric_type=metric,
                    prediction_days=prediction_days,
                    algorithm='linear_regression'  # 使用线性回归作为默认算法
                )
                
                if pred_result['success'] and pred_result['predictions']:
                    predictions[metric] = pred_result
                    
                    # 生成该指标的容量建议
                    cap_result = generate_capacity_recommendation(
                        predictions=pred_result['predictions'],
                        metric_type=metric
                    )
                    
                    if cap_result['success']:
                        recommendations[metric] = cap_result
            
            # 生成综合建议
            comprehensive_advice = self._synthesize_advice(recommendations)
            
            # 生成资源扩展计划
            expansion_plan = self._generate_expansion_plan(predictions, recommendations)
            
            # 生成成本估算
            cost_estimation = self._estimate_costs(expansion_plan)
            
            # 生成风险评估
            risk_assessment = self._assess_risks(predictions)
            
            return {
                'success': True,
                'host_ip': host_ip,
                'prediction_days': prediction_days,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'individual_metrics': {
                    metric: {
                        'predictions': predictions.get(metric, {}).get('predictions', []),
                        'recommendations': recommendations.get(metric, {}).get('recommendations', []),
                        'statistics': recommendations.get(metric, {}).get('statistics', {})
                    } for metric in metrics
                },
                'comprehensive_advice': comprehensive_advice,
                'expansion_plan': expansion_plan,
                'cost_estimation': cost_estimation,
                'risk_assessment': risk_assessment,
                'next_review_date': (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
            }
            
        except Exception as e:
            logger.error(f"生成综合容量规划时发生错误: {str(e)}")
            return {
                'success': False,
                'message': f'生成容量规划失败: {str(e)}'
            }
    
    def _synthesize_advice(self, recommendations):
        """
        综合分析各指标的建议
        """
        # 按严重性分类建议
        critical_issues = []
        warnings = []
        suggestions = []
        
        for metric, data in recommendations.items():
            for rec in data.get('recommendations', []):
                rec_item = {
                    'metric': metric,
                    'title': rec['title'],
                    'description': rec['description'],
                    'suggestion': rec['suggestion']
                }
                
                if rec['severity'] == 'high':
                    critical_issues.append(rec_item)
                elif rec['severity'] == 'medium':
                    warnings.append(rec_item)
                else:
                    suggestions.append(rec_item)
        
        # 生成综合建议文本
        summary = []
        
        if critical_issues:
            summary.append({
                'type': 'critical',
                'title': '紧急问题',
                'content': f'发现 {len(critical_issues)} 个需要立即处理的问题，请优先解决。',
                'details': critical_issues
            })
        
        if warnings:
            summary.append({
                'type': 'warning',
                'title': '警告',
                'content': f'发现 {len(warnings)} 个需要关注的问题，建议在近期处理。',
                'details': warnings
            })
        
        if suggestions:
            summary.append({
                'type': 'suggestion',
                'title': '建议',
                'content': f'以下 {len(suggestions)} 个优化建议可以帮助提高资源利用率或降低成本。',
                'details': suggestions
            })
        
        # 如果没有任何问题
        if not summary:
            summary.append({
                'type': 'normal',
                'title': '资源状态正常',
                'content': '所有资源指标在正常范围内，建议保持当前配置并继续监控。',
                'details': []
            })
        
        return summary
    
    def _generate_expansion_plan(self, predictions, recommendations):
        """
        生成资源扩展计划
        """
        expansion_plan = {}
        
        for metric, pred_data in predictions.items():
            if metric not in ['cpu', 'memory', 'disk']:  # 暂不考虑网络扩展
                continue
            
            # 检查是否需要扩展
            pred_values = [p[1] for p in pred_data.get('predictions', [])]
            if not pred_values:
                continue
            
            # 获取最大值和平均值
            max_value = max(pred_values)
            avg_value = sum(pred_values) / len(pred_values)
            
            # 获取现有建议
            metric_recommendations = recommendations.get(metric, {}).get('recommendations', [])
            needs_expansion = False
            needs_downgrade = False
            
            # 检查是否超过阈值
            if max_value > self.EXTENSION_THRESHOLDS[metric]:
                needs_expansion = True
            elif avg_value < self.DOWNGRADE_THRESHOLDS[metric]:
                needs_downgrade = True
            
            # 分析建议内容
            for rec in metric_recommendations:
                if '扩容' in rec['suggestion'] or '扩展' in rec['suggestion']:
                    needs_expansion = True
                elif '降级' in rec['suggestion'] or '整合' in rec['suggestion']:
                    needs_downgrade = True
            
            # 生成扩展/降级建议
            if needs_expansion:
                # 计算需要扩展的容量
                current_capacity_est = 100  # 假设当前容量为100%（相对值）
                target_capacity = current_capacity_est * (max_value / self.EXTENSION_THRESHOLDS[metric]) * 1.2  # 增加20%缓冲
                expansion_ratio = target_capacity / current_capacity_est
                
                # 确定扩展类型
                if expansion_ratio <= 1.5:
                    expansion_type = '适度扩展'
                elif expansion_ratio <= 2.0:
                    expansion_type = '显著扩展'
                else:
                    expansion_type = '大规模扩展'
                
                # 估算实施时间（基于扩展类型）
                implementation_time = {
                    '适度扩展': '1-2天',
                    '显著扩展': '3-5天',
                    '大规模扩展': '1-2周'
                }
                
                expansion_plan[metric] = {
                    'action': 'expand',
                    'current_estimated_usage': f'{max_value:.1f}%',
                    'suggested_expansion_ratio': f'{expansion_ratio:.2f}x',
                    'expansion_type': expansion_type,
                    'implementation_timeframe': implementation_time[expansion_type],
                    'priority': 'high' if expansion_ratio > 2.0 else 'medium',
                    'justification': f'{metric}使用峰值预计将达到{max_value:.1f}%，超过警戒线{self.EXTENSION_THRESHOLDS[metric]}%'
                }
            elif needs_downgrade:
                # 计算可以降级的容量
                current_capacity_est = 100  # 假设当前容量为100%（相对值）
                target_capacity = current_capacity_est * (avg_value / self.DOWNGRADE_THRESHOLDS[metric]) * 1.3  # 保留30%缓冲
                downgrade_ratio = target_capacity / current_capacity_est
                
                expansion_plan[metric] = {
                    'action': 'downgrade',
                    'current_estimated_usage': f'{avg_value:.1f}%',
                    'suggested_downgrade_ratio': f'{downgrade_ratio:.2f}x',
                    'potential_cost_saving': f'{(1 - downgrade_ratio) * 100:.1f}%',
                    'implementation_timeframe': '1-2天',
                    'priority': 'low',
                    'justification': f'{metric}平均使用率仅为{avg_value:.1f}%，低于优化阈值{self.DOWNGRADE_THRESHOLDS[metric]}%'
                }
            else:
                expansion_plan[metric] = {
                    'action': 'maintain',
                    'current_estimated_usage': f'最大 {max_value:.1f}%, 平均 {avg_value:.1f}%',
                    'justification': f'{metric}使用在合理范围内，建议保持当前配置'
                }
        
        return expansion_plan
    
    def _estimate_costs(self, expansion_plan):
        """
        估算扩容/降级的成本影响
        """
        cost_impact = {
            'daily_cost_changes': {},
            'monthly_cost_changes': {},
            'annual_cost_changes': {},
            'total_impact': 0
        }
        
        # 假设当前配置为中型
        current_config = 'medium'
        
        for metric, plan in expansion_plan.items():
            if metric not in self.RESOURCE_COSTS:
                continue
            
            current_cost = self.RESOURCE_COSTS[metric][current_config]
            
            if plan['action'] == 'expand':
                # 根据扩展比例选择新配置
                ratio = float(plan['suggested_expansion_ratio'].rstrip('x'))
                if ratio <= 1.5:
                    new_config = 'medium'  # 中型足够
                elif ratio <= 2.0:
                    new_config = 'large'  # 需要大型
                else:
                    # 可能需要多个大型配置
                    new_config = 'large'
                    multiple = int(ratio / 2) + 1
                
                new_cost = self.RESOURCE_COSTS[metric][new_config]
                if ratio > 2.0:
                    new_cost *= multiple
                
                daily_change = new_cost - current_cost
                
            elif plan['action'] == 'downgrade':
                # 降级到小型配置
                new_config = 'small'
                new_cost = self.RESOURCE_COSTS[metric][new_config]
                daily_change = new_cost - current_cost
                
            else:  # maintain
                daily_change = 0
            
            # 计算各类成本变化
            cost_impact['daily_cost_changes'][metric] = daily_change
            cost_impact['monthly_cost_changes'][metric] = daily_change * 30
            cost_impact['annual_cost_changes'][metric] = daily_change * 365
            cost_impact['total_impact'] += daily_change * 30  # 总月度影响
        
        # 添加总体评估
        total_monthly = cost_impact['total_impact']
        if total_monthly > 0:
            cost_impact['summary'] = f'预计月度成本增加 {abs(total_monthly):.2f} 元'
        elif total_monthly < 0:
            cost_impact['summary'] = f'预计月度成本减少 {abs(total_monthly):.2f} 元'
        else:
            cost_impact['summary'] = '预计成本无显著变化'
        
        return cost_impact
    
    def _assess_risks(self, predictions):
        """
        评估资源使用风险
        """
        risks = []
        
        for metric, pred_data in predictions.items():
            if metric not in ['cpu', 'memory', 'disk']:  # 暂不评估网络风险
                continue
            
            pred_values = [p[1] for p in pred_data.get('predictions', [])]
            if not pred_values:
                continue
            
            # 计算风险指标
            max_value = max(pred_values)
            avg_value = sum(pred_values) / len(pred_values)
            
            # 计算使用率超过阈值的时间比例
            threshold = self.EXTENSION_THRESHOLDS[metric]
            high_usage_time_ratio = sum(1 for v in pred_values if v > threshold) / len(pred_values)
            
            # 评估风险等级
            risk_level = 'low'
            risk_description = ''
            mitigation_suggestions = []
            
            if max_value > threshold * 1.2:  # 超过阈值20%以上
                risk_level = 'high'
                risk_description = f'{metric}使用率预计将显著超过警戒线，最大可能达到{max_value:.1f}%'
                mitigation_suggestions = [
                    f'立即规划{metric}扩容',
                    '考虑实施负载均衡',
                    '优化应用程序以减少资源消耗'
                ]
            elif max_value > threshold:
                risk_level = 'medium'
                risk_description = f'{metric}使用率预计将超过警戒线，最大可能达到{max_value:.1f}%'
                mitigation_suggestions = [
                    f'在{int(high_usage_time_ratio * 100)}%的时间内需要扩容',
                    '监控使用模式，优化资源分配',
                    '制定扩容计划，准备在需要时快速实施'
                ]
            elif avg_value > threshold * 0.7:
                risk_level = 'medium'
                risk_description = f'{metric}平均使用率较高({avg_value:.1f}%)，接近警戒线'
                mitigation_suggestions = [
                    '持续监控使用趋势',
                    '制定扩容预案',
                    '考虑资源优化'
                ]
            elif avg_value < self.DOWNGRADE_THRESHOLDS[metric]:
                risk_level = 'low'
                risk_description = f'{metric}使用率过低({avg_value:.1f}%)，资源可能被浪费'
                mitigation_suggestions = [
                    '考虑资源降级以节省成本',
                    '评估是否可以整合工作负载',
                    '检查是否有闲置资源'
                ]
            else:
                risk_level = 'low'
                risk_description = f'{metric}使用率在合理范围内'
                mitigation_suggestions = ['保持当前配置，继续监控']
            
            risks.append({
                'metric': metric,
                'risk_level': risk_level,
                'description': risk_description,
                'max_usage': f'{max_value:.1f}%',
                'avg_usage': f'{avg_value:.1f}%',
                'mitigation_suggestions': mitigation_suggestions
            })
        
        # 计算总体风险评级
        high_risks = sum(1 for r in risks if r['risk_level'] == 'high')
        medium_risks = sum(1 for r in risks if r['risk_level'] == 'medium')
        
        if high_risks > 0:
            overall_risk = 'high'
        elif medium_risks > 0:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'overall_risk_level': overall_risk,
            'risk_summary': f'发现{high_risks}个高风险项，{medium_risks}个中等风险项',
            'detailed_risks': risks
        }


def generate_host_capacity_plan(host_ip, prediction_days=7):
    """
    为指定主机生成容量规划
    
    Args:
        host_ip: 主机IP地址
        prediction_days: 预测天数
        
    Returns:
        容量规划结果
    """
    try:
        planner = CapacityPlanner()
        plan = planner.generate_comprehensive_plan(host_ip, prediction_days)
        
        # 添加报告元数据
        plan['report_type'] = 'capacity_plan'
        plan['report_version'] = '1.0'
        
        return plan
        
    except Exception as e:
        logger.error(f"生成主机容量规划时发生错误: {str(e)}")
        return {
            'success': False,
            'message': f'容量规划生成失败: {str(e)}'
        }


def generate_fleet_capacity_summary(host_ips, prediction_days=7):
    """
    生成多主机的容量规划摘要
    
    Args:
        host_ips: 主机IP地址列表
        prediction_days: 预测天数
        
    Returns:
        舰队容量规划摘要
    """
    try:
        fleet_summary = {
            'hosts_analyzed': len(host_ips),
            'reports_generated': 0,
            'hosts_needing_expansion': {},
            'hosts_needing_downgrade': {},
            'overall_cost_impact': 0,
            'critical_issues': [],
            'summary_by_metric': {},
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 初始化按指标统计
        metrics = ['cpu', 'memory', 'disk']
        for metric in metrics:
            fleet_summary['summary_by_metric'][metric] = {
                'hosts_needing_expansion': 0,
                'hosts_needing_downgrade': 0,
                'hosts_healthy': 0,
                'average_utilization': 0
            }
        
        # 分析每个主机
        total_utilization = {metric: 0 for metric in metrics}
        host_count = {metric: 0 for metric in metrics}
        
        for host_ip in host_ips:
            plan = generate_host_capacity_plan(host_ip, prediction_days)
            
            if plan['success']:
                fleet_summary['reports_generated'] += 1
                
                # 检查是否有严重问题
                for advice in plan.get('comprehensive_advice', []):
                    if advice['type'] == 'critical':
                        fleet_summary['critical_issues'].extend([
                            {'host': host_ip, 'issue': issue}
                            for issue in advice.get('details', [])
                        ])
                
                # 统计扩展和降级需求
                expansion_plan = plan.get('expansion_plan', {})
                for metric, action in expansion_plan.items():
                    if metric in metrics:
                        if action['action'] == 'expand':
                            if metric not in fleet_summary['hosts_needing_expansion']:
                                fleet_summary['hosts_needing_expansion'][metric] = []
                            fleet_summary['hosts_needing_expansion'][metric].append(host_ip)
                            fleet_summary['summary_by_metric'][metric]['hosts_needing_expansion'] += 1
                        elif action['action'] == 'downgrade':
                            if metric not in fleet_summary['hosts_needing_downgrade']:
                                fleet_summary['hosts_needing_downgrade'][metric] = []
                            fleet_summary['hosts_needing_downgrade'][metric].append(host_ip)
                            fleet_summary['summary_by_metric'][metric]['hosts_needing_downgrade'] += 1
                        else:
                            fleet_summary['summary_by_metric'][metric]['hosts_healthy'] += 1
                        
                        # 收集利用率数据
                        if 'current_estimated_usage' in action:
                            usage_str = action['current_estimated_usage']
                            # 提取数值（处理如"最大 80%, 平均 50%"这样的格式）
                            if '平均' in usage_str:
                                avg_part = usage_str.split('平均')[1].strip()
                                avg_value = float(avg_part.split('%')[0])
                                total_utilization[metric] += avg_value
                                host_count[metric] += 1
            
        # 计算平均利用率
        for metric in metrics:
            if host_count[metric] > 0:
                fleet_summary['summary_by_metric'][metric]['average_utilization'] = \
                    total_utilization[metric] / host_count[metric]
        
        # 生成总体建议
        fleet_summary['recommendations'] = []
        
        # 针对需要扩展的主机给出建议
        for metric, hosts in fleet_summary['hosts_needing_expansion'].items():
            if hosts:
                fleet_summary['recommendations'].append({
                    'type': 'expansion',
                    'metric': metric,
                    'affected_hosts': len(hosts),
                    'description': f'{len(hosts)} 台主机的 {metric} 资源需要扩展',
                    'suggestion': f'优先为以下主机规划 {metric} 扩容: {"、".join(hosts[:3])}{"等" if len(hosts) > 3 else ""}'
                })
        
        # 针对可以优化的主机给出建议
        for metric, hosts in fleet_summary['hosts_needing_downgrade'].items():
            if hosts:
                fleet_summary['recommendations'].append({
                    'type': 'optimization',
                    'metric': metric,
                    'affected_hosts': len(hosts),
                    'description': f'{len(hosts)} 台主机的 {metric} 资源利用率较低',
                    'suggestion': f'考虑对以下主机进行 {metric} 资源降级以节约成本: {"、".join(hosts[:3])}{"等" if len(hosts) > 3 else ""}'
                })
        
        # 生成优先级建议
        if fleet_summary['critical_issues']:
            fleet_summary['priority_action'] = '解决关键问题'
            fleet_summary['priority_description'] = f'存在 {len(fleet_summary["critical_issues"]) // 3} 个主机有紧急问题需要处理'
        elif fleet_summary['hosts_needing_expansion']:
            fleet_summary['priority_action'] = '执行扩容计划'
            # 计算需要扩容的主机总数
            total_expand_hosts = sum(len(hosts) for hosts in fleet_summary['hosts_needing_expansion'].values())
            fleet_summary['priority_description'] = f'{total_expand_hosts} 个实例需要扩容以避免性能问题'
        else:
            fleet_summary['priority_action'] = '维持现状并监控'
            fleet_summary['priority_description'] = '大多数主机资源使用正常，建议定期监控'
        
        return fleet_summary
        
    except Exception as e:
        logger.error(f"生成舰队容量摘要时发生错误: {str(e)}")
        return {
            'success': False,
            'message': f'舰队容量分析失败: {str(e)}'
        }


def generate_capacity_forecast_chart_data(plan_data):
    """
    生成容量预测图表数据
    
    Args:
        plan_data: 容量规划数据
        
    Returns:
        图表格式的数据
    """
    try:
        chart_data = {
            'metrics': {},
            'timestamps': []
        }
        
        individual_metrics = plan_data.get('individual_metrics', {})
        
        for metric, data in individual_metrics.items():
            if 'predictions' in data and data['predictions']:
                # 提取时间戳和预测值
                timestamps = [p[0] for p in data['predictions']]
                values = [p[1] for p in data['predictions']]
                
                # 为图表准备数据格式
                chart_data['metrics'][metric] = {
                    'values': values,
                    'unit': '%' if metric in ['cpu', 'memory', 'disk'] else 'KB/s',
                    'threshold': CapacityPlanner.EXTENSION_THRESHOLDS.get(metric, 80)
                }
                
                # 使用第一个指标的时间戳
                if not chart_data['timestamps'] and timestamps:
                    chart_data['timestamps'] = timestamps
        
        return chart_data
        
    except Exception as e:
        logger.error(f"生成图表数据时发生错误: {str(e)}")
        return {'metrics': {}, 'timestamps': []}
