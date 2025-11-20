from pyecsca.ec.mult import LTRMultiplier, RTLMultiplier, SlidingWindowMultiplier, CombMultiplier, ProcessingDirection

from epare.error_model import ErrorModel
from epare.config import MultIdent, Config


def only_ltr_example(config: Config, always=False, complete=False):
    """Select single LTRMultiplier example."""
    return config.mult.klass == LTRMultiplier and config.mult.kwargs["always"] == always and config.mult.kwargs["complete"] == complete


def only_rtl_example(config: Config, always=False, complete=False):
    """Select single RTLMultiplier example."""
    return config.mult.klass == RTLMultiplier and config.mult.kwargs["always"] == always and config.mult.kwargs["complete"] == complete


def only_sliding_example(config: Config, width=4, recoding_direction=ProcessingDirection.LTR):
    """Select single SlidingWindow example."""
    return config.mult.klass == SlidingWindowMultiplier and config.mult.kwargs["width"] == width and config.mult.kwargs["recoding_direction"] == recoding_direction


def only_comb_example(config: Config, width=4, always=True):
    """Select single Comb example."""
    return config.mult.klass == CombMultiplier and config.mult.kwargs["width"] == width and config.mult.kwargs["always"] == always


def only_ltrs(config: Config):
    """Select all LTRs."""
    return config.mult.klass == LTRMultiplier


def only_rtls(config: Config):
    """Select all RTLs."""
    return config.mult.klass == RTLMultiplier


def only_slidingws(config: Config):
    """Select all SlidingWindows."""
    return config.mult.klass == SlidingWindowMultiplier


def only_combs(config: Config):
    """Select all Combs (not BGMW)."""
    return config.mult.klass == CombMultiplier


def no_combs(config: Config):
    """Select all but Comb and BGMW."""
    return config.mult.klass not in (CombMultiplier, BGMWMultiplier)


def single_layer_ctr(config: Config):
    """Select configs with only a single countermeasure."""
    return all(map(lambda ident: isinstance(ident, MultIdent), config.composition.args))


def single_type_ctr(config: Config):
    """Select configs with only a single type of countermeasure (can be nested)."""
    return all(map(lambda ident: isinstance(ident, MultIdent) or ident.klass == config.composition.klass, config.composition.args))


def single_type_ctr_full(config: Config):
    """Select configs with only a single type of countermeasure that is fully nested."""
    return all(map(lambda ident: ident.klass == config.composition.klass, config.composition.args))


def fixed_error_model(config: Config):
    """Select a single example error model."""
    return config.error_model == ErrorModel({"divides"}, "all", True)


def fixed_no_countermeasure(config: Config):
    """Select configs with no countermeasures."""
    return not config.has_countermeasure


def has_gsr(config: Config):
    """Select configs with GSR."""
    return any(lambda ident: ident.klass == GroupScalarRandomization, config.countermeasures)





